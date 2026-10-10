package soar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testZone = "t.example.com"

// loopbackDial lets tests reach origins on 127.0.0.1, which the default dialer refuses.
var loopbackDial = (&net.Dialer{}).DialContext

func startServer(t *testing.T) (string, ed25519.PublicKey) {
	return startServerWith(t, ServerConfig{Dial: loopbackDial})
}

func startServerWith(t *testing.T, cfg ServerConfig) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg.Zone, cfg.PrivateKey = testZone, priv
	go Serve(ctx, pc, cfg)
	return pc.LocalAddr().String(), pub
}

// startOrigin serves "N\n" → N pattern bytes, or echoes when the request is "echo\n".
func startOrigin(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var line []byte
				b := make([]byte, 1)
				for {
					if _, err := c.Read(b); err != nil {
						return
					}
					if b[0] == '\n' {
						break
					}
					line = append(line, b[0])
				}
				if string(line) == "echo" {
					io.Copy(c, c)
					return
				}
				var n int
				fmt.Sscan(string(line), &n)
				c.Write(pattern(n))
			}()
		}
	}()
	return ln.Addr().String()
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

// lossyForwarder relays UDP to server, dropping and delaying like a bad resolver.
func lossyForwarder(t *testing.T, server string, loss float64, delay, jitter time.Duration) string {
	t.Helper()
	front, _ := net.ListenPacket("udp", "127.0.0.1:0")
	back, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { front.Close(); back.Close() })
	saddr, _ := net.ResolveUDPAddr("udp", server)
	var mu sync.Mutex
	var client net.Addr
	rng := mrand.New(mrand.NewPCG(1, 2))
	later := func(pc net.PacketConn, b []byte, to net.Addr) {
		mu.Lock()
		drop := rng.Float64() < loss
		d := delay
		if jitter > 0 {
			d += time.Duration(rng.Int64N(int64(jitter)))
		}
		mu.Unlock()
		if drop {
			return
		}
		time.AfterFunc(d, func() { pc.WriteTo(b, to) })
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			client = from
			mu.Unlock()
			later(back, append([]byte(nil), buf[:n]...), saddr)
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := back.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			to := client
			mu.Unlock()
			later(front, append([]byte(nil), buf[:n]...), to)
		}
	}()
	return front.LocalAddr().String()
}

func fetch(t *testing.T, c *Client, origin string, n int) time.Duration {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := c.DialContext(ctx, "tcp", origin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	fmt.Fprintf(conn, "%d\n", n)
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after %d bytes: %v", len(got), err)
	}
	if !bytes.Equal(got, pattern(n)) {
		t.Fatalf("got %d bytes, want %d (corrupt or short)", len(got), n)
	}
	return time.Since(start)
}

func TestE2EDirect(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	c, err := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fetch(t, c, origin, 10)
	d := fetch(t, c, origin, 1<<20)
	t.Logf("1 MiB direct: %v (%.0f KB/s)", d, 1024/d.Seconds())
}

func TestE2EEcho(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	defer c.Close()
	conn, err := c.DialContext(context.Background(), "tcp", origin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	up := make([]byte, 200<<10)
	rand.Read(up)
	go func() {
		conn.Write([]byte("echo\n"))
		conn.Write(up)
	}()
	got := make([]byte, len(up))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, up) {
		t.Fatal("echo mismatch")
	}
}

func TestE2ELossyMultipath(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	var res []string
	for range 3 {
		res = append(res, lossyForwarder(t, srv, 0.10, 40*time.Millisecond, 40*time.Millisecond))
	}
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: res})
	defer c.Close()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := fetch(t, c, origin, 100<<10)
			t.Logf("100 KiB over 3 lossy paths: %v", d)
		}()
	}
	wg.Wait()
}

func TestDefaultDialRefusesLoopback(t *testing.T) {
	srv, pub := startServerWith(t, ServerConfig{})
	origin := startOrigin(t)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	defer c.Close()
	conn, err := c.DialContext(context.Background(), "tcp", origin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "10\n")
	if _, err := io.ReadAll(conn); err == nil {
		t.Fatal("server dialed a loopback destination")
	}
}

func TestPublicOnly(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:80": false, "10.1.2.3:443": false, "169.254.169.254:80": false,
		"100.64.0.1:80": false, "[::1]:443": false, "[fd00::1]:80": false, "0.0.0.0:80": false,
		"0.1.2.3:80": false, "[::ffff:127.0.0.1]:80": false, "[64:ff9b::7f00:1]:80": false,
		"[64:ff9b::a9fe:a9fe]:80": false, "[2002:7f00:1::]:80": false, "[2001:0:1::1]:80": false,
		"[::127.0.0.1]:80": false, "[2606:4700::1111%eth0]:443": false, "[64:ff9b::7f00:1%lo0]:80": false, "[::ffff:0:7f00:1]:80": false, "[64:ff9b::808:808]:443": true, "[2002:808:808::]:443": true,
		"192.0.2.1:443": false, "198.51.100.9:80": false, "203.0.113.5:443": false,
		"8.8.8.8:443": true, "[2606:4700::1111]:443": true,
	} {
		if err := PublicOnly("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("%s: allowed=%v, want %v", addr, err == nil, ok)
		}
	}
}

func TestPublicOnlyRefusesOwnAddresses(t *testing.T) {
	addrs, _ := net.InterfaceAddrs()
	for _, ia := range addrs {
		ipn, ok := ia.(*net.IPNet)
		if !ok {
			continue
		}
		addr := net.JoinHostPort(ipn.IP.String(), "443")
		if err := PublicOnly("tcp", addr, nil); err == nil {
			t.Errorf("own address %s allowed", addr)
		}
	}
}

func TestRoundTripper(t *testing.T) {
	srv, pub := startServer(t)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(pattern(30000))
	}))
	t.Cleanup(hs.Close)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	defer c.Close()
	rt, err := c.NewRoundTripper(context.Background(), strings.TrimPrefix(hs.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt, Timeout: 30 * time.Second}).Get(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(body, pattern(30000)) {
		t.Fatalf("body %d bytes", len(body))
	}
}

// nxInjector forwards to server but first answers every query with an unsigned NXDOMAIN.
func nxInjector(t *testing.T, server string) string {
	front, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { front.Close() })
	saddr, _ := net.ResolveUDPAddr("udp", server)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := append([]byte(nil), buf[:n]...)
			if q, err := parseQuery(msg, zone{}); err == nil {
				front.WriteTo(appendAnswer(nil, q, rcodeNXDomain, nil), from)
			}
			go func() {
				back, _ := net.ListenPacket("udp", "127.0.0.1:0")
				defer back.Close()
				back.WriteTo(msg, saddr)
				back.SetReadDeadline(time.Now().Add(3 * time.Second))
				rb := make([]byte, 4096)
				if m, _, err := back.ReadFrom(rb); err == nil {
					front.WriteTo(rb[:m], from)
				}
			}()
		}
	}()
	return front.LocalAddr().String()
}

func TestForgedNXDomainIgnored(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{nxInjector(t, srv)}})
	defer c.Close()
	for range 3 {
		fetch(t, c, origin, 20<<10)
	}
}

func TestServerRestartSignedUnknownSession(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	ctx1, cancel1 := context.WithCancel(context.Background())
	go Serve(ctx1, pc, ServerConfig{Zone: testZone, PrivateKey: priv, Dial: loopbackDial})
	origin := startOrigin(t)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{addr}})
	defer c.Close()
	fetch(t, c, origin, 10<<10)

	cancel1() // the server restarts and forgets every session
	time.Sleep(100 * time.Millisecond)
	pc2, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	go Serve(ctx2, pc2, ServerConfig{Zone: testZone, PrivateKey: priv, Dial: loopbackDial})

	deadline := time.Now().Add(15 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := c.DialContext(ctx, "tcp", origin)
		cancel()
		if err == nil {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			fmt.Fprintf(conn, "%d\n", 100)
			got, err := io.ReadAll(conn)
			conn.Close()
			if err == nil && bytes.Equal(got, pattern(100)) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("client never recovered from the server restart")
		}
	}
}

func TestServerRestartUnsignedRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the liveness timeout")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	ctx1, cancel1 := context.WithCancel(context.Background())
	go Serve(ctx1, pc, ServerConfig{Zone: testZone, PrivateKey: priv, Dial: loopbackDial})
	origin := startOrigin(t)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{nxInjector(t, addr)}})
	defer c.Close()
	fetch(t, c, origin, 10<<10)
	cancel1()
	time.Sleep(100 * time.Millisecond)
	// The new server never signs, as if its signing budget were exhausted.
	pc2, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	go func() {
		buf := make([]byte, 4096)
		go func() { <-ctx2.Done(); pc2.Close() }()
		for {
			n, from, err := pc2.ReadFrom(buf)
			if err != nil {
				return
			}
			if q, err := parseQuery(buf[:n], zone{}); err == nil {
				pc2.WriteTo(appendAnswer(nil, q, rcodeNXDomain, nil), from)
			}
		}
	}()
	start := time.Now()
	for time.Since(start) < 25*time.Second {
		c.mu.Lock()
		dead := c.sess != nil && c.sess.isClosed()
		c.mu.Unlock()
		if dead {
			t.Logf("session presumed lost after %v", time.Since(start).Round(time.Second))
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("session never presumed lost")
}

func TestIdleSessionSurvivesResume(t *testing.T) {
	if testing.Short() {
		t.Skip("idles past the liveness timeout")
	}
	srv, pub := startServer(t)
	origin := startOrigin(t)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	defer c.Close()
	fetch(t, c, origin, 1000)
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	time.Sleep(deadSessionAfter + 2*time.Second)
	fetch(t, c, origin, 1000)
	time.Sleep(200 * time.Millisecond)
	c.mu.Lock()
	same := c.sess == sess && !sess.isClosed()
	c.mu.Unlock()
	if !same {
		t.Fatal("resuming after idle reset a healthy session")
	}
}

func TestPublicOnlyRefusesOwnAddressesViaNAT64(t *testing.T) {
	addrs, _ := net.InterfaceAddrs()
	for _, ia := range addrs {
		ipn, ok := ia.(*net.IPNet)
		if !ok || ipn.IP.To4() == nil {
			continue
		}
		v4 := ipn.IP.To4()
		for _, wrapped := range []string{
			fmt.Sprintf("[64:ff9b::%x%02x:%x%02x]:443", v4[0], v4[1], v4[2], v4[3]),
			fmt.Sprintf("[2002:%x%02x:%x%02x::1]:443", v4[0], v4[1], v4[2], v4[3]),
		} {
			if err := PublicOnly("tcp", wrapped, nil); err == nil {
				t.Errorf("own address %s allowed as %s", v4, wrapped)
			}
		}
	}
}

func TestResetStreamIsNeverDialed(t *testing.T) {
	var dials atomic.Int32
	srv := &Server{ctx: context.Background(), cfg: ServerConfig{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unreachable")
	}, Logger: slog.New(slog.DiscardHandler)}}
	ss := &srvSession{session: newSession(false, streamConfig{StreamWindow: 1 << 16, SendBuffer: 1 << 16, MaxStreams: 4}, nil, nil), srv: srv}
	ss.mu.Lock()
	st := ss.peerStream(0)
	dest := "example.com:443"
	st.onData(0, append([]byte{byte(len(dest))}, dest...), false)
	st.abort(ErrStreamReset) // a RESET in the same packet as the destination
	ss.mu.Unlock()
	ss.serveStream(st)
	if n := dials.Load(); n != 0 {
		t.Fatalf("dialed a reset stream %d times", n)
	}
}

func TestResetAfterFinStillDialsAndStaysCounted(t *testing.T) {
	var dials atomic.Int32
	srv := &Server{ctx: context.Background(), cfg: ServerConfig{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unreachable")
	}, Logger: slog.New(slog.DiscardHandler)}}
	ss := &srvSession{session: newSession(false, streamConfig{StreamWindow: 1 << 16, SendBuffer: 1 << 16, MaxStreams: 4}, nil, nil), srv: srv}
	ss.acceptFn = func(st *stream) bool {
		if st != nil {
			st.serving = true
		}
		return true
	}
	dest := "example.com:443"
	var pkt []byte
	pkt = appendStream(pkt, 0, 0, append([]byte{byte(len(dest))}, dest...), true, false)
	pkt = ctrl{typ: frReset, id: 0}.appendTo(pkt)
	ss.mu.Lock()
	if _, err := ss.receive(0, pkt, time.Now()); err != nil {
		t.Fatal(err)
	}
	st := ss.streams[0]
	ss.mu.Unlock()
	if st == nil {
		t.Fatal("stream released while serveStream still owns it")
	}
	ss.serveStream(st)
	if n := dials.Load(); n != 1 {
		t.Fatalf("FIN then RESET (client closed after writing): %d dials, want 1", n)
	}
}

func TestWriteThenCloseDeliversRequest(t *testing.T) {
	srv, pub := startServer(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- b
	}()
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	defer c.Close()
	conn, err := c.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	req := []byte("fire and forget\n")
	conn.Write(req)
	conn.Close() // Close promises written data is still delivered
	select {
	case b := <-got:
		if !bytes.Equal(b, req) {
			t.Fatalf("destination got %q, want %q", b, req)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("request written before Close never reached the destination")
	}
}

// nameLimiter forwards only queries whose name is at most max characters, like resolvers in
// networks that drop long names; longer ones get SERVFAIL.
func nameLimiter(t *testing.T, server string, max int) string {
	front, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { front.Close() })
	saddr, _ := net.ResolveUDPAddr("udp", server)
	z, _ := parseZone(testZone)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := append([]byte(nil), buf[:n]...)
			q, err := parseQuery(msg, z)
			if err != nil {
				continue
			}
			if end, _ := skipName(msg, hdrLen); end-hdrLen-2 > max {
				front.WriteTo(appendAnswer(nil, q, rcodeServFail, nil), from)
				continue
			}
			go func() {
				back, _ := net.ListenPacket("udp", "127.0.0.1:0")
				defer back.Close()
				back.WriteTo(msg, saddr)
				back.SetReadDeadline(time.Now().Add(3 * time.Second))
				rb := make([]byte, 4096)
				if m, _, err := back.ReadFrom(rb); err == nil {
					front.WriteTo(rb[:m], from)
				}
			}()
		}
	}()
	return front.LocalAddr().String()
}

func TestNameProbeRespectsShortNameLimit(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{nameLimiter(t, srv, 101)}})
	defer c.Close()
	for range 5 {
		fetch(t, c, origin, 2000)
	}
	// An upload large enough to need full-size queries must still get through.
	conn, err := c.DialContext(context.Background(), "tcp", origin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	up := make([]byte, 20<<10)
	rand.Read(up)
	go func() {
		conn.Write([]byte("echo\n"))
		conn.Write(up)
	}()
	got := make([]byte, len(up))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("upload through a 101-char resolver: %v", err)
	}
	c.mu.Lock()
	nameLen := c.paths[0].nameLen
	c.mu.Unlock()
	if nameLen > 101 {
		t.Fatalf("path promoted to %d-char names through a 101-char resolver", nameLen)
	}
}

func TestRelayClosesDestinationWhenStreamDies(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	closed := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Read(make([]byte, 1)) // returns once the relay closes its end
		close(closed)
		c.Close()
	}()
	up, _ := net.Dial("tcp", ln.Addr().String())
	s := newSession(false, streamConfig{StreamWindow: 1 << 16, SendBuffer: 1 << 16, MaxStreams: 4}, nil, nil)
	s.mu.Lock()
	st := s.peerStream(0)
	st.onData(0, nil, true) // the client half-closed at once
	s.mu.Unlock()
	go relay(&Conn{st: st}, up)
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	st.abort(ErrStreamReset)
	s.mu.Unlock()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("destination left open after the stream died")
	}
}

func TestResetAfterGappedFinDoesNotSpin(t *testing.T) {
	s, st := newTestStream(t)
	s.client = false
	st.onData(10, []byte("tail"), true) // FIN beyond a gap at [0,10)
	reset := ctrl{typ: frReset, id: st.id}.appendTo(nil)
	s.mu.Lock()
	s.receive(0, reset, time.Now())
	s.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := (&Conn{st: st}).Read(make([]byte, 10))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read returned data from a gap")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read never returned after a reset with a gap before FIN")
	}
}

func TestIdleClientStopsPolling(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	fwd, count := countingForwarder(t, srv)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{fwd}})
	defer c.Close()
	fetch(t, c, origin, 2000)
	time.Sleep(2 * time.Second) // let acks and closes settle
	before := count.Load()
	time.Sleep(3 * time.Second)
	if n := count.Load() - before; n > 0 {
		t.Fatalf("idle client sent %d queries in 3s", n)
	}
}

func countingForwarder(t *testing.T, server string) (string, *atomic.Int64) {
	var n atomic.Int64
	front, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { front.Close() })
	saddr, _ := net.ResolveUDPAddr("udp", server)
	back, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { back.Close() })
	var mu sync.Mutex
	var client net.Addr
	go func() {
		buf := make([]byte, 4096)
		for {
			m, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			n.Add(1)
			mu.Lock()
			client = from
			mu.Unlock()
			back.WriteTo(buf[:m], saddr)
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			m, _, err := back.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			to := client
			mu.Unlock()
			front.WriteTo(buf[:m], to)
		}
	}()
	return front.LocalAddr().String(), &n
}

func TestHelloFloodDoesNotStallSessions(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	defer c.Close()
	fetch(t, c, origin, 1000)
	z, _ := parseZone(testZone)
	flood, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer flood.Close()
	saddr, _ := net.ResolveUDPAddr("udp", srv)
	stop := make(chan struct{})
	go func() {
		eph := make([]byte, 2+pubLen)
		for i := uint16(1); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			rand.Read(eph[2:])
			flood.WriteTo(appendQuery(nil, i, eph, z, typeTXT, 1232), saddr)
		}
	}()
	defer close(stop)
	time.Sleep(200 * time.Millisecond)
	if d := fetch(t, c, origin, 50<<10); d > 10*time.Second {
		t.Fatalf("50 KiB took %v during a hello flood", d)
	}
}

func TestDefaultDialAllowsOnlyWebPorts(t *testing.T) {
	cfg := ServerConfig{}
	cfg.setDefaults()
	if _, err := cfg.Dial(context.Background(), "tcp", "8.8.8.8:25"); err == nil || !strings.Contains(err.Error(), "port not allowed") {
		t.Fatalf("port 25: %v", err)
	}
}

type orderCache struct {
	mu     sync.Mutex
	stores [][]string
}

func (o *orderCache) Load() []string { return nil }
func (o *orderCache) Store(r []string) {
	time.Sleep(5 * time.Millisecond) // a slow cache must still see snapshots in order
	o.mu.Lock()
	o.stores = append(o.stores, slices.Clone(r))
	o.mu.Unlock()
}

func TestDiscoveryCachesTCPVerifiedResolvers(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	// A resolver reachable only over TCP: UDP to it goes nowhere.
	tcpOnly := tcpOnlyResolver(t, srv)
	cache := &orderCache{}
	c, err := NewClient(Config{Zone: testZone, ServerKey: pub, TCP: "on", Discovery: Discovery{
		Enabled: true, Candidates: []string{tcpOnly}, Cache: cache, noBundled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fetch(t, c, origin, 2000)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cache.mu.Lock()
		n := len(cache.stores)
		last := []string(nil)
		if n > 0 {
			last = cache.stores[n-1]
		}
		cache.mu.Unlock()
		if slices.Contains(last, tcpOnly) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("TCP-verified resolver never cached")
}

// tcpOnlyResolver accepts RFC 7766 TCP queries and forwards them to server over UDP.
func tcpOnlyResolver(t *testing.T, server string) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	saddr, _ := net.ResolveUDPAddr("udp", server)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var wmu sync.Mutex
				var hdr [2]byte
				for {
					if _, err := io.ReadFull(c, hdr[:]); err != nil {
						return
					}
					msg := make([]byte, int(hdr[0])<<8|int(hdr[1]))
					if _, err := io.ReadFull(c, msg); err != nil {
						return
					}
					go func() {
						back, _ := net.ListenPacket("udp", "127.0.0.1:0")
						defer back.Close()
						back.WriteTo(msg, saddr)
						back.SetReadDeadline(time.Now().Add(3 * time.Second))
						rb := make([]byte, 4096)
						m, _, err := back.ReadFrom(rb)
						if err != nil {
							return
						}
						wmu.Lock()
						c.Write(append([]byte{byte(m >> 8), byte(m)}, rb[:m]...))
						wmu.Unlock()
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestAmplificationBudget(t *testing.T) {
	s := &Server{cfg: ServerConfig{MaxBytesPerPrefix: 4000}, rrl: make(map[netip.Prefix]*byteBucket)}
	victim := &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 53}
	// Unamplified replies never draw on the budget, so spoofed junk can't drain it.
	for range 1000 {
		if !s.allowAmplification(victim, 0) {
			t.Fatal("zero-amplification reply refused")
		}
	}
	allowed := 0
	for range 100 {
		if s.allowAmplification(victim, 500) {
			allowed++
		}
	}
	if allowed > 2 {
		t.Fatalf("%d amplified answers allowed against a 1000-byte burst", allowed)
	}
	// A full table sends new prefixes to the shared overflow budget, not unlimited.
	for i := range maxRRLPrefixes - len(s.rrl) {
		s.rrl[netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)] = &byteBucket{}
	}
	other := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 53}
	n := 0
	for range 100 {
		if s.allowAmplification(other, 500) {
			n++
		}
	}
	if n > 2 || len(s.rrl) > maxRRLPrefixes {
		t.Fatalf("overflow: %d allowed, table %d", n, len(s.rrl))
	}
}

func TestSafeQNameMustFitHello(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	zone := strings.Repeat("z", 40) + ".example.com" // a hello needs ~55 chars, plus this
	_, err := NewClient(Config{Zone: zone, ServerKey: pub, Resolvers: []string{"127.0.0.1:53"}})
	if err == nil {
		t.Fatal("SafeQName 101 accepted for a zone that pushes the hello past it")
	}
	c, err := NewClient(Config{Zone: zone, ServerKey: pub, Resolvers: []string{"127.0.0.1:53"}, SafeQName: 140})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestCloseFlushesNewestCacheSnapshot(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	good := lossyForwarder(t, srv, 0, 5*time.Millisecond, 0)
	cache := &orderCache{}
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Discovery: Discovery{
		Enabled: true, Candidates: []string{good}, Cache: cache, noBundled: true,
	}})
	fetch(t, c, origin, 1000)
	c.Close()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if n := len(cache.stores); n == 0 || !slices.Contains(cache.stores[n-1], good) {
		t.Fatalf("after Close the cache holds %v, want the verified %s", cache.stores, good)
	}
}

func TestNewRoundTripperFailsWhenDestinationUnreachable(t *testing.T) {
	srv, pub := startServer(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close() // nothing listens here: the server's dial is refused
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.NewRoundTripper(ctx, dead); err == nil {
		t.Fatal("NewRoundTripper succeeded though the destination is unreachable")
	}
}

// errInjector forwards to server but first answers every query with a forged error.
func errInjector(t *testing.T, server string, rcode byte, tc bool) string {
	front, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { front.Close() })
	saddr, _ := net.ResolveUDPAddr("udp", server)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := append([]byte(nil), buf[:n]...)
			if q, err := parseQuery(msg, zone{}); err == nil {
				forged := appendAnswer(nil, q, rcode, nil)
				if tc {
					forged[2] |= 0x02
				}
				front.WriteTo(forged, from)
			}
			go func() {
				back, _ := net.ListenPacket("udp", "127.0.0.1:0")
				defer back.Close()
				back.WriteTo(msg, saddr)
				back.SetReadDeadline(time.Now().Add(3 * time.Second))
				rb := make([]byte, 4096)
				if m, _, err := back.ReadFrom(rb); err == nil {
					front.WriteTo(rb[:m], from)
				}
			}()
		}
	}()
	return front.LocalAddr().String()
}

func TestForgedErrorsDoNotCutQueriesShort(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode byte
		trunc bool
	}{{"refused", rcodeRefused, false}, {"servfail", rcodeServFail, false}, {"truncated", rcodeOK, true}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, pub := startServer(t)
			origin := startOrigin(t)
			c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{errInjector(t, srv, tc.rcode, tc.trunc)}})
			defer c.Close()
			if d := fetch(t, c, origin, 50<<10); d > 5*time.Second {
				t.Fatalf("50 KiB took %v under forged %s answers", d, tc.name)
			}
			c.mu.Lock()
			p := c.paths[0]
			qtype, ceil := p.qtype, p.sizeCeil
			c.mu.Unlock()
			if qtype != typeTXT || ceil != limitClasses {
				t.Fatalf("forged answers changed the path: qtype=%d sizeCeil=%d", qtype, ceil)
			}
		})
	}
}

// qminResolver mimics a resolver doing QNAME minimisation (RFC 9156): before each query it asks
// for every ancestor under the zone with type A, one label at a time, and gives up with that
// answer's rcode unless it's NOERROR.
func qminResolver(t *testing.T, server string) string {
	front, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { front.Close() })
	saddr, _ := net.ResolveUDPAddr("udp", server)
	z, _ := parseZone(testZone)
	ask := func(msg []byte) ([]byte, error) {
		back, _ := net.ListenPacket("udp", "127.0.0.1:0")
		defer back.Close()
		back.WriteTo(msg, saddr)
		back.SetReadDeadline(time.Now().Add(3 * time.Second))
		rb := make([]byte, 4096)
		n, _, err := back.ReadFrom(rb)
		return rb[:n], err
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := append([]byte(nil), buf[:n]...)
			go func() {
				q, err := parseQuery(msg, z)
				if err != nil {
					return
				}
				// Labels left of the zone, rightmost first.
				var labels [][]byte
				for i := hdrLen; msg[i] != 0; i += 1 + int(msg[i]) {
					labels = append(labels, msg[i+1:i+1+int(msg[i])])
				}
				zl := strings.Count(testZone, ".") + 1
				for k := 1; k < len(labels)-zl+1; k++ {
					var name []byte
					for _, l := range labels[len(labels)-zl-k:] {
						name = append(name, byte(len(l)))
						name = append(name, l...)
					}
					m := []byte{0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
					m = append(append(m, name...), 0, 0, 1, 0, 1) // type A
					a, err := ask(m)
					if err != nil || a[3]&0x0F != rcodeOK {
						code := byte(rcodeServFail)
						if err == nil {
							code = a[3] & 0x0F
						}
						front.WriteTo(appendAnswer(nil, q, code, nil), from)
						return
					}
				}
				if a, err := ask(msg); err == nil {
					front.WriteTo(a, from)
				}
			}()
		}
	}()
	return front.LocalAddr().String()
}

func TestTunnelThroughQNAMEMinimisingResolver(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	c, _ := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{qminResolver(t, srv)}})
	defer c.Close()
	fetch(t, c, origin, 20<<10)
}

func TestApexSOAAndNoData(t *testing.T) {
	z, _ := parseZone(testZone)
	for _, tc := range []struct {
		name  string
		qtype uint16
		an    int
	}{{testZone, typeSOA, 1}, {testZone, 2 /* NS */, 0}, {"abc." + testZone, 1 /* A */, 0}} {
		var name []byte
		for _, l := range strings.Split(tc.name, ".") {
			name = append(append(name, byte(len(l))), l...)
		}
		m := append([]byte{0, 9, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, name...)
		m = append(m, 0, byte(tc.qtype>>8), byte(tc.qtype), 0, 1)
		q, err := parseQuery(m, z)
		if err != nil || !q.inZone {
			t.Fatalf("%s: inZone=%v err=%v", tc.name, q != nil && q.inZone, err)
		}
		ans := appendNoData(nil, q, z)
		a, err := parseAnswer(ans)
		if err != nil || a.rcode != rcodeOK || ans[2]&0x04 == 0 || int(ans[7]) != tc.an {
			t.Fatalf("%s type %d: rcode=%d aa=%v an=%d err=%v", tc.name, tc.qtype, a.rcode, ans[2]&0x04 != 0, ans[7], err)
		}
	}
}

func TestTCPOnlyThroughCustomDialer(t *testing.T) {
	srv, pub := startServer(t)
	origin := startOrigin(t)
	res := tcpOnlyResolver(t, srv)
	var dials atomic.Int32
	c, err := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{res}, TCP: "only",
		DialTCP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fetch(t, c, origin, 30<<10)
	if dials.Load() == 0 {
		t.Fatal("custom TCP dialer unused")
	}
}
