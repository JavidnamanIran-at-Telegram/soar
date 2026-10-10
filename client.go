package seep

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Config configures a tunnel client.
type Config struct {
	Zone      string
	ServerKey ed25519.PublicKey
	// Resolvers are recursive resolvers (host:port) to tunnel through. All are used at once.
	Resolvers []string
	// SafeQName is the name length every path starts at; some networks drop longer names (Iran
	// ~101). Paths probe up to MaxQName. Defaults 101 and 253.
	SafeQName, MaxQName int
	// Hold is how long the server may hold an idle poll. Default 500ms.
	Hold time.Duration
	// MaxInflight caps queries outstanding across all paths. Default 128.
	MaxInflight int
	// MaxPathWindow caps one path's queries outstanding. Default 32.
	MaxPathWindow int
	StreamWindow  uint64 // per-stream receive window. Default 256 KiB.
	SendBuffer    int    // per-stream send buffer. Default 64 KiB.
	MaxStreams    int    // Default 64.
	Logger        *slog.Logger
}

func (c *Config) setDefaults() {
	if c.SafeQName <= 0 {
		c.SafeQName = 101
	}
	if c.MaxQName <= 0 {
		c.MaxQName = maxName
	}
	c.MaxQName = min(c.MaxQName, maxName)
	c.SafeQName = min(c.SafeQName, c.MaxQName)
	if c.Hold <= 0 {
		c.Hold = 500 * time.Millisecond
	}
	if c.MaxInflight <= 0 {
		c.MaxInflight = 128
	}
	if c.MaxPathWindow <= 0 {
		c.MaxPathWindow = 32
	}
	if c.StreamWindow == 0 {
		c.StreamWindow = 256 << 10
	}
	if c.SendBuffer <= 0 {
		c.SendBuffer = 64 << 10
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 64
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
}

const (
	limitClasses   = 16 // answer limit = 512 + 48*class
	outcomeWindow  = 20
	lateGrace      = 3 * time.Second
	helloRetry     = time.Second
	maxHelloPaths  = 16
	nxdomainToDead = 4
)

// Client tunnels streams through DNS.
type Client struct {
	cfg Config
	z   zone
	pc  net.PacketConn

	mu      sync.Mutex
	paths   []*path
	pending map[uint16]*pendingQuery
	sess    *clientSession
	wakeCh  chan struct{}
	done    chan struct{}
	once    sync.Once

	lastDump time.Time
}

type path struct {
	addr      *net.UDPAddr
	srtt      time.Duration
	rttvar    time.Duration
	hasRTT    bool
	cwnd      float64
	ssthresh  float64
	inflight  int
	outcomes  [outcomeWindow]bool // true = lost
	outIdx    int
	outN      int
	lastCut   time.Time
	consec    int
	suspended time.Time
	dead      bool

	nameLen    int // current QNAME cap
	probeFails int
	probing    bool
	successes  int

	limitClass int
	lastHello  time.Time

	verified    bool // has answered at least once
	lastSuccess time.Time
	nextSeq     uint64
	maxAnswered uint64 // highest seq answered + 1
}

type pendingQuery struct {
	txn      uint16
	p        *path
	sess     *clientSession
	question []byte
	sent     time.Time
	deadline time.Time
	pn       uint64
	hello    bool
	probe    bool
	expired  bool
	seq      uint64 // per-path send order
	scout    bool   // carries no data: a hello or a probe of an unverified path
}

type clientSession struct {
	*session
	sid         uint16
	eph         *ecdh.PrivateKey
	ready       chan struct{}
	established bool
	backlog     int
	nx          int
}

func (cs *clientSession) isClosed() bool {
	if cs.session == nil {
		return false
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.closed
}

// NewClient starts a client. It handshakes lazily on the first Dial.
func NewClient(cfg Config) (*Client, error) {
	cfg.setDefaults()
	if len(cfg.ServerKey) != ed25519.PublicKeySize {
		return nil, errors.New("seep: client needs the server's Ed25519 public key")
	}
	z, err := parseZone(cfg.Zone)
	if err != nil {
		return nil, err
	}
	if len(cfg.Resolvers) == 0 {
		return nil, errors.New("seep: no resolvers")
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	c := &Client{cfg: cfg, z: z, pc: pc, pending: make(map[uint16]*pendingQuery),
		wakeCh: make(chan struct{}, 1), done: make(chan struct{})}
	for _, r := range cfg.Resolvers {
		if err := c.addPathLocked(r); err != nil {
			cfg.Logger.Warn("bad resolver", "resolver", r, "err", err)
		}
	}
	if len(c.paths) == 0 {
		pc.Close()
		return nil, errors.New("seep: no usable resolvers")
	}
	go c.readLoop()
	go c.run()
	return c, nil
}

func (c *Client) addPathLocked(r string) error {
	ua, err := net.ResolveUDPAddr("udp", r)
	if err != nil {
		return err
	}
	for _, p := range c.paths {
		if p.addr.String() == ua.String() {
			return nil
		}
	}
	c.paths = append(c.paths, &path{addr: ua, cwnd: 4, ssthresh: float64(c.cfg.MaxPathWindow),
		nameLen: c.cfg.SafeQName, limitClass: limitClasses - 1})
	return nil
}

// Close shuts the client down.
func (c *Client) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.pc.Close()
		c.mu.Lock()
		if c.sess != nil && c.sess.session != nil {
			c.sess.close(ErrClosed)
		}
		c.mu.Unlock()
	})
	return nil
}

func (c *Client) wake() { signal(c.wakeCh) }

// DialContext opens a stream to addr (host:port) through the tunnel.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if len(addr) == 0 || len(addr) > 255 {
		return nil, errors.New("seep: bad address")
	}
	cs, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	cs.mu.Lock()
	st, err := cs.openStream()
	if err != nil {
		cs.mu.Unlock()
		return nil, err
	}
	st.sbuf = append(append(st.sbuf, byte(len(addr))), addr...)
	st.spending.add(0, uint64(len(st.sbuf)))
	cs.mu.Unlock()
	c.wake()
	return &Conn{st: st, local: c.pc.LocalAddr(), remote: tunnelAddr(addr)}, nil
}

type tunnelAddr string

func (a tunnelAddr) Network() string { return "seep" }
func (a tunnelAddr) String() string  { return string(a) }

// session returns an established session, handshaking if needed.
func (c *Client) session(ctx context.Context) (*clientSession, error) {
	c.mu.Lock()
	cs := c.sess
	if cs != nil && cs.isClosed() {
		cs = nil
	}
	if cs == nil {
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		cs = &clientSession{eph: eph, ready: make(chan struct{})}
		c.sess = cs
		for _, p := range c.paths {
			p.lastHello = time.Time{}
		}
	}
	c.mu.Unlock()
	c.wake()
	select {
	case <-cs.ready:
		if cs.session == nil {
			return nil, ErrClosed
		}
		return cs, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, ErrClosed
	}
}

func (c *Client) run() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		now := time.Now()
		c.mu.Lock()
		c.expireLocked(now)
		c.fillLocked(now)
		if debugOn && now.Sub(c.lastDump) > 250*time.Millisecond {
			c.lastDump = now
			line := ""
			for _, p := range c.paths {
				line += fmt.Sprintf(" [%s cw=%.1f in=%d rtt=%v loss=%.2f v=%v]", p.addr.IP, p.cwnd, p.inflight, p.srtt.Round(time.Millisecond), p.lossRate(), p.verified)
			}
			if c.sess != nil && c.sess.session != nil {
				c.sess.mu.Lock()
				line += fmt.Sprintf(" backlog=%d sent=%d lostQ=%d", c.sess.backlog, len(c.sess.sent), len(c.sess.lostQ))
				c.sess.mu.Unlock()
			}
			dbg("cli paths%s", line)
		}
		next := c.nextDeadlineLocked(now)
		c.mu.Unlock()
		timer.Reset(next)
		select {
		case <-c.wakeCh:
		case <-timer.C:
		case <-c.done:
			return
		}
	}
}

func (c *Client) nextDeadlineLocked(now time.Time) time.Duration {
	next := now.Add(time.Second)
	for _, q := range c.pending {
		d := q.deadline
		if q.expired {
			d = d.Add(lateGrace)
		}
		if d.Before(next) {
			next = d
		}
	}
	for _, p := range c.paths {
		if p.suspended.After(now) && p.suspended.Before(next) {
			next = p.suspended
		}
	}
	return max(next.Sub(now), time.Millisecond)
}

func (p *path) usable(now time.Time) bool { return !p.dead && !p.suspended.After(now) }

// rto is how long a query on p may take before it's presumed lost, excluding any hold.
func (p *path) rto() time.Duration {
	if !p.hasRTT {
		return time.Second
	}
	return min(max(p.srtt+max(4*p.rttvar, 50*time.Millisecond), 200*time.Millisecond), 3*time.Second)
}

func (p *path) lossRate() float64 {
	if p.outN == 0 {
		return 0
	}
	n := 0
	for i := range p.outN {
		if p.outcomes[i] {
			n++
		}
	}
	return float64(n) / float64(p.outN)
}

func (p *path) record(lost bool) {
	p.outcomes[p.outIdx] = lost
	p.outIdx = (p.outIdx + 1) % outcomeWindow
	p.outN = min(p.outN+1, outcomeWindow)
}

func (p *path) onSuccess(now time.Time, rtt time.Duration, maxWin int) {
	p.record(false)
	p.consec = 0
	p.verified = true
	p.lastSuccess = now
	p.successes++
	if rtt > 0 {
		if !p.hasRTT {
			p.srtt, p.rttvar, p.hasRTT = rtt, rtt/2, true
		} else {
			d := p.srtt - rtt
			if d < 0 {
				d = -d
			}
			p.rttvar = (3*p.rttvar + d) / 4
			p.srtt = (7*p.srtt + rtt) / 8
		}
	}
	if p.cwnd < p.ssthresh {
		p.cwnd++
	} else {
		p.cwnd += 1 / p.cwnd
	}
	p.cwnd = min(p.cwnd, float64(maxWin))
}

// onLoss backs off on runs of losses. Random loss is scattered among successes; a resolver's
// rate limit drops every query past its budget, so overload shows up as consecutive losses.
func (p *path) onLoss(now time.Time) {
	p.record(true)
	p.consec++
	if p.consec >= 3 && now.Sub(p.lastCut) > p.rto() {
		p.cwnd = max(1, p.cwnd*0.7)
		p.ssthresh = max(2, p.cwnd)
		p.lastCut = now
	}
	if p.consec >= 5 && now.Sub(p.lastSuccess) > 2*time.Second {
		backoff := min(time.Duration(1<<min(p.consec-5, 4))*time.Second, 15*time.Second)
		p.suspended = now.Add(backoff)
		p.cwnd = 1
	}
}

func (c *Client) expireLocked(now time.Time) {
	for txn, q := range c.pending {
		if q.expired {
			if now.After(q.deadline.Add(lateGrace)) {
				delete(c.pending, txn)
			}
			continue
		}
		// Packet threshold: three later queries on this path were answered.
		early := q.p.hasRTT && q.p.maxAnswered >= q.seq+4 && now.Sub(q.sent) > q.p.srtt+2*q.p.rttvar
		if now.Before(q.deadline) && !early {
			continue
		}
		q.expired = true
		c.failLocked(q, now, false)
	}
}

// failLocked handles a query that got no usable answer.
func (c *Client) failLocked(q *pendingQuery, now time.Time, refused bool) {
	p := q.p
	p.inflight--
	if q.probe {
		p.probing = false
		p.probeFails++
	}
	if refused {
		p.consec += 2
	}
	p.onLoss(now)
	if q.hello || q.sess == nil || q.sess.session == nil {
		return
	}
	cs := q.sess
	cs.mu.Lock()
	cs.declareLost(q.pn)
	cs.lostQ = append(cs.lostQ, q.pn)
	cs.mu.Unlock()
}

// wantQueries is how many queries the session wants outstanding with nothing else to send.
func (cs *clientSession) wantQueries() int {
	if len(cs.streams) == 0 {
		if len(cs.toAck) > 0 || len(cs.sent) > 0 {
			return 1
		}
		return 0
	}
	return 2 + cs.backlog
}

func (c *Client) fillLocked(now time.Time) {
	cs := c.sess
	if cs == nil {
		return
	}
	if !cs.established {
		c.sendHellosLocked(cs, now)
		return
	}
	if cs.closed {
		return
	}
	for {
		inflight, polls := 0, 0
		for _, q := range c.pending {
			if !q.expired {
				inflight++
				if !q.scout {
					polls++
				}
			}
		}
		if inflight >= c.cfg.MaxInflight {
			return
		}
		cs.mu.Lock()
		need := cs.hasData() || polls < cs.wantQueries()
		cs.mu.Unlock()
		if !need {
			return
		}
		p := c.pickPathLocked(now)
		if p == nil {
			return
		}
		c.sendDataLocked(cs, p, now, true)
	}
}

// pickPathLocked returns the path with a free slot and the earliest expected answer.
func (c *Client) pickPathLocked(now time.Time) *path {
	var best *path
	var bestScore float64
	for _, p := range c.paths {
		if !p.usable(now) || float64(p.inflight) >= p.cwnd || (!p.verified && p.inflight > 0) {
			continue
		}
		rtt := p.rto()
		if p.hasRTT {
			rtt = p.srtt
		}
		score := float64(rtt) * (1 + float64(p.inflight)/p.cwnd) / (1 - min(p.lossRate(), 0.9))
		if best == nil || score < bestScore {
			best, bestScore = p, score
		}
	}
	return best
}

func (c *Client) newTxnLocked() uint16 {
	for {
		var b [2]byte
		rand.Read(b[:])
		t := binary.BigEndian.Uint16(b[:])
		if _, ok := c.pending[t]; !ok {
			return t
		}
	}
}

func (c *Client) sendHellosLocked(cs *clientSession, now time.Time) {
	payload := make([]byte, 2, 2+pubLen)
	payload = append(payload, cs.eph.PublicKey().Bytes()...)
	sent := 0
	for _, p := range c.paths {
		if sent >= maxHelloPaths {
			break
		}
		if !p.usable(now) || p.inflight > 0 || now.Sub(p.lastHello) < helloRetry {
			continue
		}
		p.lastHello = now
		c.sendLocked(p, &pendingQuery{p: p, sess: cs, hello: true, scout: true}, payload, now, time.Second)
		sent++
	}
}

func (c *Client) sendDataLocked(cs *clientSession, p *path, now time.Time, allowDup bool) {
	nameLen := p.nameLen
	probe := false
	if !p.probing && p.successes >= 3 && p.nameLen < c.cfg.MaxQName && p.probeFails < 2 {
		nameLen, probe, p.probing = c.cfg.MaxQName, true, true
	}
	budget := c.z.maxPayload(nameLen) - 4 - tagLen - 1
	if !p.verified {
		budget = minPlain // probe: don't strand data on a path that may be dead
	}
	holdClass := min(int(c.cfg.Hold/(100*time.Millisecond)), 15)
	hdr := byte(holdClass<<4 | p.limitClass)

	cs.mu.Lock()
	pn, plain, data, pkt := cs.build([]byte{hdr}, budget, now, 0)
	dup := allowDup && pkt != nil && len(pkt.streams) > 0 && p.verified && !cs.hasData()
	var ad [4]byte
	binary.BigEndian.PutUint16(ad[:], cs.sid)
	binary.BigEndian.PutUint16(ad[2:], uint16(pn))
	sealed := cs.seal.seal(nil, ad[:], plain, pn)
	cs.mu.Unlock()
	dbg("cli send pn=%d path=%s plain=%x", pn, p.addr, plain)
	m := cs.seal.mask(sealed)
	payload := make([]byte, 0, 4+len(sealed))
	payload = append(payload, ad[0], ad[1], ad[2]^m[0], ad[3]^m[1])
	payload = append(payload, sealed...)

	timeout := p.rto()
	if !data {
		timeout += c.cfg.Hold
	}
	c.sendLocked(p, &pendingQuery{p: p, sess: cs, pn: pn, probe: probe, scout: !p.verified}, payload, now, timeout)
	// The tail of an upload (often a whole request) goes out twice, on another path if there is one.
	if dup {
		if p2 := c.pickPathLocked(now); p2 != nil && p2.verified {
			cs.mu.Lock()
			ok := cs.requeue(pkt)
			cs.mu.Unlock()
			if ok {
				c.sendDataLocked(cs, p2, now, false)
			}
		}
	}
}

func (c *Client) sendLocked(p *path, q *pendingQuery, payload []byte, now time.Time, timeout time.Duration) {
	q.txn = c.newTxnLocked()
	msg := appendQuery(make([]byte, 0, 300), q.txn, payload, c.z, 1232)
	end, err := skipName(msg, hdrLen)
	if err != nil {
		return
	}
	q.question = msg[hdrLen : end+4]
	q.sent, q.deadline = now, now.Add(timeout)
	q.seq = p.nextSeq
	p.nextSeq++
	c.pending[q.txn] = q
	p.inflight++
	if _, err := c.pc.WriteTo(msg, p.addr); err != nil {
		c.cfg.Logger.Debug("send failed", "resolver", p.addr, "err", err)
	}
}

func (c *Client) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, _, err := c.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		c.onAnswer(buf[:n])
	}
}

func (c *Client) onAnswer(msg []byte) {
	a, err := parseAnswer(msg)
	if err != nil {
		dbg("cli parse err %v len=%d", err, len(msg))
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.wake()
	defer c.mu.Unlock()
	q := c.pending[a.txn]
	// Off-path injectors can't match the question; on-path ones fail authentication below.
	if q == nil || !bytes.EqualFold(a.question, q.question) {
		dbg("cli no match txn=%d q=%v", a.txn, q != nil)
		return
	}
	p := q.p
	late := q.expired
	p.maxAnswered = max(p.maxAnswered, q.seq+1)
	if a.tc {
		p.limitClass = max(0, p.limitClass-4)
	}
	if a.tc || a.rcode != rcodeOK || !a.hasTXT {
		dbg("cli fail tc=%v rcode=%d txt=%v hello=%v", a.tc, a.rcode, a.hasTXT, q.hello)
		if a.rcode == rcodeNXDomain && q.sess != nil && q.sess.established && !q.hello {
			if q.sess.nx++; q.sess.nx >= nxdomainToDead {
				q.sess.close(errors.New("seep: server lost the session"))
			}
		}
		if !late {
			delete(c.pending, a.txn)
			c.failLocked(q, now, a.rcode == rcodeRefused)
		}
		return
	}
	if q.hello {
		c.onHelloLocked(q, a.txt, now)
		return
	}
	cs := q.sess
	if cs == nil || cs.session == nil || len(a.txt) < 2+sampleLen {
		return
	}
	sealed := a.txt[2:]
	m := cs.open.mask(sealed)
	ad := [2]byte{a.txt[0] ^ m[0], a.txt[1] ^ m[1]}
	cs.mu.Lock()
	pn := decodePN(cs.largestRecv, cs.haveRecv, binary.BigEndian.Uint16(ad[:]))
	plain, err := cs.open.open(ad[:], sealed, pn)
	if err != nil || len(plain) < 2 {
		cs.mu.Unlock()
		dbg("cli auth fail pn=%d err=%v", pn, err)
		return // forged or corrupt: keep waiting for the real answer
	}
	delete(c.pending, a.txn)
	dbg("cli recv pn=%d for up=%d plain=%x", pn, q.pn, plain)
	cs.nx = 0
	held := time.Duration(plain[0]) * 10 * time.Millisecond
	cs.backlog = int(plain[1])
	if _, err := cs.receive(pn, plain[2:], now); err != nil {
		cs.closeLocked(err)
	}
	if sp := cs.sent[q.pn]; sp != nil {
		cs.acked(sp)
	}
	cs.mu.Unlock()
	if late {
		return
	}
	p.inflight--
	if q.probe {
		p.probing = false
		p.nameLen = c.cfg.MaxQName
	}
	p.onSuccess(now, now.Sub(q.sent)-held, c.cfg.MaxPathWindow)
}

func (c *Client) onHelloLocked(q *pendingQuery, reply []byte, now time.Time) {
	cs := q.sess
	p := q.p
	sid, up, down, err := clientFinish(c.cfg.ServerKey, cs.eph, reply)
	if err != nil {
		return // forged
	}
	delete(c.pending, q.txn)
	if !q.expired {
		p.inflight--
		p.onSuccess(now, now.Sub(q.sent), c.cfg.MaxPathWindow)
	}
	if cs.established {
		return
	}
	cfg := streamConfig{StreamWindow: c.cfg.StreamWindow, SendBuffer: c.cfg.SendBuffer, MaxStreams: c.cfg.MaxStreams}
	cs.session = newSession(true, cfg, up, down)
	cs.wakeFn = c.wake
	cs.sid = sid
	cs.established = true
	close(cs.ready)
}
