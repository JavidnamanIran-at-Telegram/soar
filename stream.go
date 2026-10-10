package seep

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

var (
	ErrStreamReset = errors.New("seep: stream reset by peer")
	ErrClosed      = errors.New("seep: closed")
)

// stream is one tunneled connection. All mutable state is guarded by the session mutex.
type stream struct {
	id uint64
	s  *session

	// Send side. sbuf holds bytes [sbase, sbase+len(sbuf)); everything below sbase is acked.
	sbuf      []byte
	sbase     uint64
	spending  rangeSet // ranges to send or retransmit
	sacked    rangeSet // acked ranges above sbase
	smax      uint64   // the peer's flow-control limit
	sfin      bool     // the app closed its write side
	sfinSent  bool     // a FIN is in flight (pending acks or loss)
	sfinAcked bool
	scap      int // bytes the app may buffer

	// Receive side. rbuf holds contiguous bytes from rread; rooo out-of-order segments by offset.
	rbuf      []byte
	rread     uint64
	rooo      map[uint64][]byte
	roooBytes int
	rfin      bool
	rfinOff   uint64
	rwin      uint64 // window size
	rmax      uint64 // limit we last advertised
	rclosed   bool   // the app closed its read side; arriving data is discarded

	reset    bool // aborted by either side
	resetErr error

	readCh, writeCh chan struct{}
	rdl, wdl        deadline
}

func newStream(s *session, id uint64) *stream {
	return &stream{
		id: id, s: s,
		smax: initialWindow, scap: s.cfg.SendBuffer,
		rwin: s.cfg.StreamWindow, rmax: initialWindow,
		readCh: make(chan struct{}, 1), writeCh: make(chan struct{}, 1),
	}
}

// initialWindow is every stream's flow-control limit until the receiver advertises its own.
const initialWindow = 32 << 10

// advertise sends the receive window if it's larger than the initial one. Caller holds s.mu.
func (st *stream) advertise() {
	if st.rwin > st.rmax {
		st.rmax = st.rwin
		st.s.queueCtrl(ctrl{typ: frMaxStream, id: st.id, val: st.rmax})
	}
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (st *stream) rcontig() uint64 { return st.rread + uint64(len(st.rbuf)) }

func (st *stream) send() uint64 { return st.sbase + uint64(len(st.sbuf)) }

// onData handles a STREAM frame. Caller holds s.mu.
func (st *stream) onData(off uint64, data []byte, fin bool) error {
	end := off + uint64(len(data))
	if end > st.rmax {
		return errors.New("seep: peer exceeded stream flow control")
	}
	if fin {
		if st.rfin && st.rfinOff != end {
			return errors.New("seep: inconsistent stream FIN")
		}
		st.rfin, st.rfinOff = true, end
	}
	if st.rclosed || st.reset {
		signal(st.readCh)
		return nil
	}
	c := st.rcontig()
	if end <= c {
		if fin {
			signal(st.readCh)
		}
		return nil
	}
	if off > c {
		if old, ok := st.rooo[off]; !ok || len(old) < len(data) {
			if st.rooo == nil {
				st.rooo = make(map[uint64][]byte)
			}
			if st.roooBytes+len(data) > 2*int(st.rwin) {
				return nil // drop; the peer will retransmit
			}
			st.roooBytes += len(data) - len(old)
			st.rooo[off] = append([]byte(nil), data...)
		}
		return nil
	}
	st.rbuf = append(st.rbuf, data[c-off:]...)
	for merged := true; merged && len(st.rooo) > 0; {
		merged = false
		for o, d := range st.rooo {
			c = st.rcontig()
			if o > c {
				continue
			}
			if e := o + uint64(len(d)); e > c {
				st.rbuf = append(st.rbuf, d[c-o:]...)
			}
			st.roooBytes -= len(d)
			delete(st.rooo, o)
			merged = true
		}
	}
	signal(st.readCh)
	return nil
}

// onAcked records that the peer received [lo, hi) and maybe the FIN. Caller holds s.mu.
func (st *stream) onAcked(lo, hi uint64, fin bool) {
	st.sacked.add(lo, hi)
	st.spending.remove(lo, hi)
	if base := st.sacked.coveredFrom(st.sbase); base > st.sbase {
		st.sbuf = st.sbuf[base-st.sbase:]
		if len(st.sbuf) == 0 {
			st.sbuf = nil
		}
		st.sbase = base
		st.sacked.trimBelow(base)
		signal(st.writeCh)
	}
	if fin {
		st.sfinAcked = true
	}
	st.s.maybeRemove(st)
}

// onLost requeues [lo, hi) minus whatever has been acked since. Caller holds s.mu.
func (st *stream) onLost(lo, hi uint64, fin bool) {
	if st.reset {
		return
	}
	lo = max(lo, st.sbase)
	if lo < hi {
		st.spending.add(lo, hi)
		for _, a := range st.sacked {
			st.spending.remove(a.lo, a.hi)
		}
	}
	if fin && !st.sfinAcked {
		st.sfinSent = false
	}
}

// wantsSend reports whether the stream has something sendable now. Caller holds s.mu.
func (st *stream) wantsSend() bool {
	if st.reset {
		return false
	}
	if len(st.spending) > 0 && st.spending[0].lo < st.smax {
		return true
	}
	return st.sfin && !st.sfinSent && !st.sfinAcked && len(st.spending) == 0
}

// doneSending: every byte and the FIN are acked, or the stream was reset.
func (st *stream) doneSending() bool { return st.reset || (st.sfin && st.sfinAcked) }

func (st *stream) doneReceiving() bool {
	return st.reset || st.rclosed || (st.rfin && st.rread == st.rfinOff)
}

func (st *stream) abort(err error) {
	st.reset, st.resetErr = true, err
	st.sbuf, st.spending, st.sacked = nil, nil, nil
	st.rooo, st.roooBytes = nil, 0
	signal(st.readCh)
	signal(st.writeCh)
}

// Conn wraps a stream as a net.Conn.
type Conn struct {
	st     *stream
	local  net.Addr
	remote net.Addr
}

func (c *Conn) Read(p []byte) (int, error) {
	st, s := c.st, c.st.s
	for {
		s.mu.Lock()
		if len(st.rbuf) > 0 {
			n := copy(p, st.rbuf)
			st.rbuf = st.rbuf[n:]
			if len(st.rbuf) == 0 {
				st.rbuf = nil
			}
			st.rread += uint64(n)
			// Re-advertise once half the window has been consumed.
			grant := false
			if limit := st.rread + st.rwin; limit-st.rmax >= st.rwin/2 && !st.rfin {
				st.rmax = limit
				s.queueCtrl(ctrl{typ: frMaxStream, id: st.id, val: limit})
				grant = true
			}
			s.maybeRemove(st)
			s.mu.Unlock()
			if grant {
				s.wake()
			}
			return n, nil
		}
		if st.rfin && st.rread == st.rfinOff {
			s.maybeRemove(st)
			s.mu.Unlock()
			return 0, io.EOF
		}
		if st.reset {
			err := st.resetErr
			s.mu.Unlock()
			return 0, err
		}
		if st.rclosed {
			s.mu.Unlock()
			return 0, net.ErrClosed
		}
		s.mu.Unlock()
		if err := st.rdl.wait(st.readCh, s.done); err != nil {
			return 0, err
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	st, s := c.st, c.st.s
	written := 0
	for written < len(p) {
		s.mu.Lock()
		if st.reset {
			err := st.resetErr
			s.mu.Unlock()
			return written, err
		}
		if st.sfin {
			s.mu.Unlock()
			return written, net.ErrClosed
		}
		if room := st.scap - len(st.sbuf); room > 0 {
			n := min(room, len(p)-written)
			start := st.send()
			st.sbuf = append(st.sbuf, p[written:written+n]...)
			st.spending.add(start, start+uint64(n))
			written += n
			s.mu.Unlock()
			s.wake()
			continue
		}
		s.mu.Unlock()
		if err := st.wdl.wait(st.writeCh, s.done); err != nil {
			return written, err
		}
	}
	return written, nil
}

// CloseWrite sends a FIN: the peer reads EOF after the data written so far.
func (c *Conn) CloseWrite() error {
	s := c.st.s
	s.mu.Lock()
	c.st.sfin = true
	s.mu.Unlock()
	s.wake()
	return nil
}

// Close closes both directions. Data already written is still delivered.
func (c *Conn) Close() error {
	st, s := c.st, c.st.s
	s.mu.Lock()
	st.sfin = true
	if !st.doneReceiving() {
		st.rclosed = true
		st.rbuf, st.rooo, st.roooBytes = nil, nil, 0
		// Ask the peer to stop sending; our own data is unaffected unless already done.
		if st.doneSending() || len(st.sbuf) == 0 {
			s.queueCtrl(ctrl{typ: frReset, id: st.id})
			st.abort(net.ErrClosed)
		}
	}
	s.maybeRemove(st)
	s.mu.Unlock()
	signal(st.readCh)
	signal(st.writeCh)
	s.wake()
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.local }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) SetDeadline(t time.Time) error {
	c.st.rdl.set(t)
	c.st.wdl.set(t)
	signal(c.st.readCh)
	signal(c.st.writeCh)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.st.rdl.set(t)
	signal(c.st.readCh)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.st.wdl.set(t)
	signal(c.st.writeCh)
	return nil
}

// deadline is a settable deadline for blocking waits.
type deadline struct {
	mu sync.Mutex
	t  time.Time
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	d.t = t
	d.mu.Unlock()
}

// wait blocks until ch is signaled, the deadline passes, or done closes.
func (d *deadline) wait(ch <-chan struct{}, done <-chan struct{}) error {
	d.mu.Lock()
	t := d.t
	d.mu.Unlock()
	if t.IsZero() {
		select {
		case <-ch:
			return nil
		case <-done:
			return ErrClosed
		}
	}
	dur := time.Until(t)
	if dur <= 0 {
		return os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(dur)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-done:
		return ErrClosed
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}
