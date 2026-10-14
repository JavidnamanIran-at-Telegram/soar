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
	c := gapClient(t, Config{Resolvers: []string{"192.0.2.1:53"}, TCP: "off",
		Discovery: Discovery{Enabled: true, Want: 1, Candidates: []string{"192.0.2.2:53"}, noBundled: true}})
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.lastCand = time.Time{}
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
	c := gapClient(t, Config{TCP: "off", Discovery: Discovery{Enabled: true,
		Candidates: []string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"}, noBundled: true}})
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.lastCand = now
	if d := c.nextDeadlineLocked(now); d > 2*c.cfg.Discovery.Pace {
		t.Fatalf("next wakeup in %v, want within the %v pace", d, c.cfg.Discovery.Pace)
	}
}
