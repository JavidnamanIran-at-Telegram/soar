package soar

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// tcpLink carries one path's queries to a resolver over TCP, pipelined on one connection
// (RFC 7766). Some networks intercept or block UDP/53 but leave TCP/53 alone (Russia since
// 2026-08). The link redials with backoff for as long as the client runs.
type tcpLink struct {
	addr     string
	out      chan []byte
	up       atomic.Bool
	done     chan struct{}
	stopOnce sync.Once
}

func (c *Client) startTCP(addr string) *tcpLink {
	l := &tcpLink{addr: addr, out: make(chan []byte, 256), done: make(chan struct{})}
	go l.run(c)
	return l
}

// stop ends the link, as when discovery prunes its path.
func (l *tcpLink) stop() { l.stopOnce.Do(func() { close(l.done) }) }

// send queues msg; a full queue drops it, which the query's timeout treats as loss.
func (l *tcpLink) send(msg []byte) {
	select {
	case l.out <- msg:
	default:
	}
}

func (l *tcpLink) run(c *Client) {
	backoff := time.Second
	for {
		select {
		case <-c.done:
			return
		case <-l.done:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := c.cfg.DialTCP(ctx, "tcp", l.addr)
		cancel()
		if err != nil {
			select {
			case <-c.done:
				return
			case <-l.done:
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, 30*time.Second)
			continue
		}
		backoff = time.Second
		l.up.Store(true)
		c.wake()
		l.serve(c, conn)
		l.up.Store(false)
	}
}

// serve relays until the connection fails or the client closes.
func (l *tcpLink) serve(c *Client, conn net.Conn) {
	errc := make(chan struct{})
	go func() {
		defer close(errc)
		var hdr [2]byte
		buf := make([]byte, 65535)
		for {
			// A black-holed connection accepts writes for a long time; an idle read deadline
			// closes it so the link redials (resolvers drop idle TCP/53 anyway, RFC 7766).
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))
			if _, err := io.ReadFull(conn, buf[:n]); err != nil {
				return
			}
			c.onAnswer(buf[:n])
		}
	}()
	defer conn.Close()
	for {
		select {
		case <-c.done:
			return
		case <-l.done:
			return
		case <-errc:
			return
		case msg := <-l.out:
			framed := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(msg)), uint16(len(msg)))
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(append(framed, msg...)); err != nil {
				return
			}
		}
	}
}
