package emu

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// StartOrigin starts a TCP origin: a client sends "N\n" and receives N bytes of a fixed pattern,
// then the connection closes. It measures time-to-first-byte and throughput without HTTP or TLS.
func StartOrigin(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveOrigin(c)
		}
	}()
	return ln.Addr().String(), nil
}

func serveOrigin(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Minute))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 0 {
		return
	}
	buf := make([]byte, 16<<10)
	for i := range buf {
		buf[i] = Pattern(i)
	}
	for sent := 0; sent < n; {
		k := min(len(buf), n-sent)
		if _, err := c.Write(buf[:k]); err != nil {
			return
		}
		sent += k
	}
}

// Pattern is the byte at offset i of every origin response (a fixed period-16K pattern), so the
// fetcher can verify integrity without holding the expected bytes.
func Pattern(i int) byte { return byte(i*7 + i>>8) }

// Fetch requests n bytes over conn and returns time to first byte and total time; it verifies the
// bytes against Pattern.
func Fetch(conn net.Conn, n int, deadline time.Time) (ttfb, total time.Duration, err error) {
	defer conn.Close()
	conn.SetDeadline(deadline)
	start := time.Now()
	if _, err := fmt.Fprintf(conn, "%d\n", n); err != nil {
		return 0, 0, err
	}
	buf := make([]byte, 32<<10)
	got := 0
	for got < n {
		k, err := conn.Read(buf)
		if k > 0 && got == 0 {
			ttfb = time.Since(start)
		}
		for j := 0; j < k; j++ {
			if buf[j] != Pattern((got+j)%(16<<10)) {
				return ttfb, time.Since(start), fmt.Errorf("corrupt byte at %d", got+j)
			}
		}
		got += k
		if err != nil {
			if err == io.EOF && got == n {
				break
			}
			return ttfb, time.Since(start), fmt.Errorf("after %d/%d bytes: %w", got, n, err)
		}
	}
	return ttfb, time.Since(start), nil
}
