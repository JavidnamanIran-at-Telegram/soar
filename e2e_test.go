package soar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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
		"[::127.0.0.1]:80": false, "[::ffff:0:7f00:1]:80": false, "[64:ff9b::808:808]:443": true, "[2002:808:808::]:443": true,
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
	rt, err := c.NewRoundTripper(context.Background(), "")
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
