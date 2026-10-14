package soar

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// gapClient builds a client that never reaches anything (TEST-NET resolvers), for tests that
// drive its internals under c.mu.
func gapClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cfg.Zone, cfg.ServerKey = testZone, pub
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// enableDiscovery turns discovery on with cands, under c.mu. Tests build the client with it off,
// so its run loop can't add a candidate before the test takes the lock.
func enableDiscovery(c *Client, want int, cands ...string) {
	c.cfg.Discovery.Enabled, c.cfg.Discovery.Want, c.cfg.Discovery.noBundled = true, want, true
	c.cfg.Discovery.setDefaults()
	c.cands, c.candIdx = cands, 0
}

// establish gives c a session as if a handshake had completed.
func establish(c *Client) *clientSession {
	cs := &clientSession{ready: make(chan struct{}), established: true, sid: 1}
	cs.session = newSession(true, streamConfig{StreamWindow: 1 << 16, SendBuffer: 1 << 16, MaxStreams: 4}, &packetCipher{}, &packetCipher{})
	close(cs.ready)
	c.sess = cs
	return cs
}

// A verified path on a run of losses isn't healthy, though as the last usable path it's kept
// usable: discovery must look for a replacement instead of counting it toward Want.
func TestDiscoveryResumesWhenVerifiedPathFails(t *testing.T) {
	c := gapClient(t, Config{Resolvers: []string{"192.0.2.1:53"}, TCP: "off"})
	c.mu.Lock()
	defer c.mu.Unlock()
	enableDiscovery(c, 1, "192.0.2.2:53")
	now := time.Now()
	p := c.paths[0]
	p.verified = true
	c.discoverLocked(now)
	if len(c.paths) != 1 {
		t.Fatal("a healthy path should be enough")
	}
	for range 6 {
		p.onLoss(now)
	}
	p.suspended = time.Time{} // the last usable path is never suspended
	c.discoverLocked(now)
	if len(c.paths) != 2 {
		t.Fatal("discovery didn't resume with the next candidate")
	}
}

// With more resolvers than maxHelloPaths, hello retries rotate through all of them.
func TestHelloRetriesRotate(t *testing.T) {
	var resolvers []string
	for i := 1; i <= 20; i++ {
		resolvers = append(resolvers, fmt.Sprintf("192.0.2.%d:53", i))
	}
	c := gapClient(t, Config{Resolvers: resolvers, TCP: "off"})
	c.mu.Lock()
	defer c.mu.Unlock()
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cs := &clientSession{eph: eph, ready: make(chan struct{})}
	t0 := time.Now()
	c.sendHellosLocked(cs, t0)
	for _, p := range c.paths {
		p.inflight = 0 // the hellos expired unanswered
	}
	t1 := t0.Add(helloRetry + time.Millisecond)
	c.sendHellosLocked(cs, t1)
	for _, p := range c.paths[16:] {
		if !p.lastHello.Equal(t1) {
			t.Fatalf("resolver %s was never tried", p.addr)
		}
	}
}

// The tail copy of an upload respects MaxInflight.
func TestTailCopyRespectsMaxInflight(t *testing.T) {
	c := gapClient(t, Config{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, TCP: "off", MaxInflight: 1})
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.paths {
		p.verified = true
	}
	cs := establish(c)
	cs.mu.Lock()
	st, _ := cs.openStream()
	st.sbuf = append(st.sbuf, "\x03a:1GET"...)
	st.spending.add(0, uint64(len(st.sbuf)))
	cs.mu.Unlock()
	c.fillLocked(time.Now())
	if n := len(c.pending); n != 1 {
		t.Fatalf("%d queries in flight with MaxInflight 1", n)
	}
}

// MaxInflight is capped, and once the DNS ID space is nearly full nothing more is sent, so
// newTxnLocked always finds a free ID.
func TestDNSIDSpaceStaysBounded(t *testing.T) {
	c := gapClient(t, Config{Resolvers: []string{"192.0.2.1:53"}, TCP: "off", MaxInflight: 1_000_000})
	if c.cfg.MaxInflight != maxInflightCap {
		t.Fatalf("MaxInflight %d, want the cap %d", c.cfg.MaxInflight, maxInflightCap)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for txn := range maxPending {
		c.pending[uint16(txn)] = &pendingQuery{p: c.paths[0], expired: true, deadline: now.Add(time.Minute)}
	}
	cs := establish(c)
	cs.mu.Lock()
	st, _ := cs.openStream()
	st.sbuf = append(st.sbuf, "\x03a:1"...)
	st.spending.add(0, uint64(len(st.sbuf)))
	cs.mu.Unlock()
	c.paths[0].verified = true
	c.fillLocked(now)
	if len(c.pending) != maxPending {
		t.Fatal("sent with the DNS ID space at its ceiling")
	}
}

// The run loop wakes when discovery's pace allows the next candidate, not a second later.
func TestDiscoveryPaceSchedulesAWakeup(t *testing.T) {
	c := gapClient(t, Config{Resolvers: []string{"192.0.2.1:53"}, TCP: "off"})
	c.mu.Lock()
	defer c.mu.Unlock()
	enableDiscovery(c, 16, "192.0.2.2:53", "192.0.2.3:53", "192.0.2.4:53")
	now := time.Now()
	c.lastCand = now
	if d := c.nextDeadlineLocked(now); d > 2*c.cfg.Discovery.Pace {
		t.Fatalf("next wakeup in %v, want within the %v pace", d, c.cfg.Discovery.Pace)
	}
}

// MaxStreams is capped so that legitimate streams can't overflow the control queue.
func TestMaxStreamsCapped(t *testing.T) {
	c := gapClient(t, Config{Resolvers: []string{"192.0.2.1:53"}, TCP: "off", MaxStreams: 100_000})
	if c.cfg.MaxStreams != maxStreamsCap {
		t.Fatalf("client MaxStreams %d, want %d", c.cfg.MaxStreams, maxStreamsCap)
	}
	sc := ServerConfig{MaxStreams: 100_000}
	sc.setDefaults()
	if sc.MaxStreams != maxStreamsCap {
		t.Fatalf("server MaxStreams %d, want %d", sc.MaxStreams, maxStreamsCap)
	}
	if 3*maxStreamsCap >= maxCtrlQueue {
		t.Fatal("capped streams could still fill the control queue")
	}
}

// An authenticated answer restarts the liveness clock while other queries are still out, so if
// every path then dies the session is still presumed lost.
func TestLivenessClockRestartsWithQueriesOut(t *testing.T) {
	c := gapClient(t, Config{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, TCP: "off"})
	c.mu.Lock()
	for _, p := range c.paths {
		p.verified = true
	}
	cs := establish(c)
	cs.mu.Lock()
	st, _ := cs.openStream()
	st.sbuf = append(st.sbuf, "\x03a:1"...)
	st.spending.add(0, uint64(len(st.sbuf)))
	cs.mu.Unlock()
	now := time.Now()
	c.fillLocked(now)
	var q *pendingQuery
	for _, p := range c.pending {
		if !p.hello {
			q = p
			break
		}
	}
	if q == nil || len(c.pending) < 2 {
		c.mu.Unlock()
		t.Fatalf("want two queries out, have %d", len(c.pending))
	}
	c.mu.Unlock()
	// The server's answer to one of them, sealed with the session's (zero) keys.
	plain := []byte{0, 0, frPing, 0, 0, 0}
	payload := (&packetCipher{}).sealDown(0, q.pn, plain)
	c.onAnswer(appendAnswer(nil, &query{txn: q.txn, question: q.question, qtype: typeTXT}, rcodeOK, payload))
	c.mu.Lock()
	defer c.mu.Unlock()
	if cs.unanswered.IsZero() {
		t.Fatal("the liveness clock stopped with a query still out")
	}
	c.checkLivenessLocked(time.Now().Add(deadSessionAfter + time.Second))
	if !cs.isClosed() {
		t.Fatal("the session wasn't presumed lost")
	}
}

// When advertising a new peer stream overflows the control queue and ends the session, the
// slot acceptFn reserved for it is given back exactly once.
func TestPeerStreamReturnsReservedSlotOnOverflow(t *testing.T) {
	cfg := streamConfig{StreamWindow: 1 << 16, SendBuffer: 1 << 16, MaxStreams: 4}
	s := newSession(false, cfg, nil, nil)
	slots := int64(1) // another session's stream
	s.acceptFn = func(st *stream) bool {
		if st == nil {
			slots++
		}
		return true
	}
	s.streamGone = func() { slots-- }
	for len(s.ctrlQ) < maxCtrlQueue {
		s.ctrlQ = append(s.ctrlQ, ctrl{typ: frOpened, id: uint64(100 + len(s.ctrlQ))})
	}
	// A new stream: acceptFn reserves a slot, then its window grant overflows the queue.
	s.receive(0, appendStream(nil, 0, 0, []byte("x"), false, false), time.Now())
	if !s.closed || slots != 1 {
		t.Fatalf("closed=%v slots=%d, want closed with 1 (the other session's)", s.closed, slots)
	}
}
