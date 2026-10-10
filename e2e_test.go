package seep

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"
)

const testZone = "t.example.com"

func startServer(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Serve(ctx, pc, ServerConfig{Zone: testZone, PrivateKey: priv})
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
