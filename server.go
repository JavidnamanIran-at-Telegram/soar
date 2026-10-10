package soar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ServerConfig configures a tunnel server: the authoritative name server for Zone.
type ServerConfig struct {
	Zone       string
	PrivateKey ed25519.PrivateKey
	// Dial connects streams to their destinations. Default: net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// MaxHold caps how long an idle poll is held waiting for data. Default 1.5s.
	MaxHold time.Duration
	// LossTimeout declares a downstream packet lost if neither acked nor reported. Default 3s.
	LossTimeout time.Duration
	// IdleTimeout ends sessions that send nothing. Default 2m.
	IdleTimeout time.Duration
	// MaxSessions caps concurrent sessions. Default 8192.
	MaxSessions int
	// MaxTotalStreams caps open streams across all sessions. Default 16384.
	MaxTotalStreams int
	StreamWindow    uint64
	SendBuffer      int
	MaxStreams      int
	Logger          *slog.Logger
}

func (c *ServerConfig) setDefaults() {
	if c.Dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second, Control: PublicOnly}
		c.Dial = d.DialContext
	}
	if c.MaxSessions <= 0 || c.MaxSessions > 1<<15 {
		c.MaxSessions = 8192
	}
	if c.MaxTotalStreams <= 0 {
		c.MaxTotalStreams = 16384
	}
	if c.MaxHold <= 0 {
		c.MaxHold = 1500 * time.Millisecond
	}
	if c.LossTimeout <= 0 {
		c.LossTimeout = 3 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 2 * time.Minute
	}
	// Uploads are small; a modest receive window bounds what one session can make us buffer.
	if c.StreamWindow == 0 {
		c.StreamWindow = 64 << 10
	}
	if c.SendBuffer <= 0 {
		c.SendBuffer = 256 << 10
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 128
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
}

// Server is a running tunnel server.
type Server struct {
	cfg ServerConfig
	z   zone
	pc  net.PacketConn
	ctx context.Context

	mu       sync.Mutex
	sessions map[uint16]*srvSession
	hellos   map[[pubLen]byte]*helloEntry
	streams  atomic.Int64

	signTokens tokenBucket
}

type helloEntry struct {
	reply []byte
	at    time.Time
	sid   uint16
}

type srvSession struct {
	*session
	srv       *Server
	sid       uint16
	created   time.Time
	used      atomic.Bool  // a valid data packet arrived: the hello wasn't just noise
	held      []*heldQuery // guarded by session.mu
	lastSeen  time.Time    // guarded by session.mu
	abandoned rangeSet     // upstream pns the client gave up on; guarded by session.mu
}

type heldQuery struct {
	q        *query
	addr     net.Addr
	upPN     uint64
	limit    int
	at       time.Time
	answered bool
}

// Serve runs a server on pc until ctx ends.
func Serve(ctx context.Context, pc net.PacketConn, cfg ServerConfig) error {
	cfg.setDefaults()
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("soar: server needs an Ed25519 private key")
	}
	z, err := parseZone(cfg.Zone)
	if err != nil {
		return err
	}
	s := &Server{cfg: cfg, z: z, pc: pc, ctx: ctx, signTokens: tokenBucket{rate: 200, tokens: 200, last: time.Now()},
		sessions: make(map[uint16]*srvSession), hellos: make(map[[pubLen]byte]*helloEntry)}
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go s.sweep()
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		// Held queries outlive this read: give each message its own copy.
		s.handle(append([]byte(nil), buf[:n]...), addr)
	}
}

func (s *Server) reply(q *query, addr net.Addr, rcode byte, payload []byte) {
	s.pc.WriteTo(appendAnswer(make([]byte, 0, 512), q, rcode, payload), addr)
}

func (s *Server) handle(msg []byte, addr net.Addr) {
	q, err := parseQuery(msg, s.z)
	if err != nil {
		return
	}
	if q.payload == nil || (q.qtype != typeTXT && q.qtype != typeAAAA) {
		s.reply(q, addr, rcodeRefused, nil)
		return
	}
	p := q.payload
	if len(p) < 2 {
		s.reply(q, addr, rcodeNXDomain, nil)
		return
	}
	sid := binary.BigEndian.Uint16(p)
	if sid == 0 {
		s.hello(q, addr, p[2:])
		return
	}
	s.mu.Lock()
	ss := s.sessions[sid]
	s.mu.Unlock()
	if ss == nil {
		s.replyUnknown(q, addr)
		return
	}
	if len(p) < 4+minPlain+tagLen {
		s.reply(q, addr, rcodeNXDomain, nil)
		return
	}
	ss.onQuery(q, addr, p)
}

// replyUnknown tells the client its session is gone, signed over the question so an injector
// can't forge it. Signing is rate-limited, so random session ids can't make us burn CPU; past the
// limit the reply goes unsigned and the client ignores it.
func (s *Server) replyUnknown(q *query, addr net.Addr) {
	if !s.signTokens.take(time.Now()) {
		s.reply(q, addr, rcodeNXDomain, nil)
		return
	}
	s.reply(q, addr, rcodeNXDomain, ed25519.Sign(s.cfg.PrivateKey, unknownSessionMsg(q.question)))
}

// tokenBucket is a mutex-guarded rate limiter: rate per second, burst of rate.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
}

func (b *tokenBucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens = min(b.rate, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) hello(q *query, addr net.Addr, eph []byte) {
	if len(eph) < pubLen {
		s.reply(q, addr, rcodeNXDomain, nil)
		return
	}
	var key [pubLen]byte
	copy(key[:], eph)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Resolvers retry and clients send the hello down several paths: answer each copy alike.
	if h := s.hellos[key]; h != nil {
		s.reply(q, addr, rcodeOK, h.reply)
		return
	}
	if len(s.sessions) >= s.cfg.MaxSessions && !s.evictUnusedLocked() {
		s.reply(q, addr, rcodeRefused, nil)
		return
	}
	var sid uint16
	for sid == 0 || s.sessions[sid] != nil {
		var b [2]byte
		rand.Read(b[:])
		sid = binary.BigEndian.Uint16(b[:])
	}
	reply, up, down, err := serverHello(s.cfg.PrivateKey, key[:], sid)
	if err != nil {
		s.reply(q, addr, rcodeNXDomain, nil)
		return
	}
	cfg := streamConfig{StreamWindow: s.cfg.StreamWindow, SendBuffer: s.cfg.SendBuffer, MaxStreams: s.cfg.MaxStreams}
	ss := &srvSession{session: newSession(false, cfg, down, up), srv: s, sid: sid, lastSeen: time.Now(), created: time.Now()}
	ss.wakeFn = ss.flush
	ss.acceptFn = func(st *stream) bool {
		if st == nil {
			return s.streams.Load() < int64(s.cfg.MaxTotalStreams)
		}
		s.streams.Add(1)
		go func() {
			defer s.streams.Add(-1)
			ss.serveStream(st)
		}()
		return true
	}
	// The client gave up on a query we haven't answered: don't spend data on it, since an answer
	// lost now would never be reported.
	ss.onLostUnknown = func(up uint64) {
		for i, h := range ss.held {
			if h.upPN == up {
				h.answered = true
				ss.held = append(ss.held[:i], ss.held[i+1:]...)
				break
			}
		}
		ss.abandoned.add(up, up+1)
		if len(ss.abandoned) > 256 {
			ss.abandoned = ss.abandoned[len(ss.abandoned)-256:]
		}
	}
	s.sessions[sid] = ss
	// Bounded by MaxSessions: entries go with their session (see evictUnusedLocked and sweep).
	s.hellos[key] = &helloEntry{reply: reply, at: time.Now(), sid: sid}
	s.reply(q, addr, rcodeOK, reply)
}

// evictUnusedLocked drops the oldest session that never sent a valid data packet, so a flood of
// hellos can't lock real clients out. Caller holds s.mu.
func (s *Server) evictUnusedLocked() bool {
	var victim *srvSession
	for _, ss := range s.sessions {
		if !ss.used.Load() && (victim == nil || ss.created.Before(victim.created)) {
			victim = ss
		}
	}
	if victim == nil {
		return false
	}
	delete(s.sessions, victim.sid)
	s.forgetHelloLocked(victim.sid)
	go victim.close(ErrClosed)
	return true
}

// forgetHelloLocked drops the cached hello reply for sid. Caller holds s.mu.
func (s *Server) forgetHelloLocked(sid uint16) {
	for k, h := range s.hellos {
		if h.sid == sid {
			delete(s.hellos, k)
			return
		}
	}
}

// onQuery handles a data query: it applies the client's packet, then answers now or holds the
// query until there's data to send.
func (ss *srvSession) onQuery(q *query, addr net.Addr, p []byte) {
	sealed := p[4:]
	m := ss.open.mask(sealed)
	var hdr [4]byte
	copy(hdr[:], p[:4])
	hdr[2] ^= m[0]
	hdr[3] ^= m[1]
	trunc := binary.BigEndian.Uint16(hdr[2:])
	now := time.Now()

	ss.mu.Lock()
	pn := decodePN(ss.largestRecv, ss.haveRecv, trunc)
	plain, err := ss.open.open(hdr[:], sealed, pn)
	if err != nil || len(plain) < 1 {
		ss.mu.Unlock()
		ss.srv.reply(q, addr, rcodeNXDomain, nil)
		return
	}
	dbg("srv q pn=%d plain=%x", pn, plain)
	ss.lastSeen = now
	ss.used.Store(true)
	limitClass, holdClass := int(plain[0]&0x0F), int(plain[0]>>4)
	ss.rxData = false
	if _, err := ss.receive(pn, plain[1:], now); err != nil {
		ss.closeLocked(err)
	}
	hq := &heldQuery{q: q, addr: addr, upPN: pn, limit: min(512+48*limitClass, q.edns), at: now}
	hold := min(time.Duration(holdClass)*100*time.Millisecond, ss.srv.cfg.MaxHold)
	var out []sendItem
	if ss.abandoned.contains(pn) {
		out = append(out, ss.emptyAnswerLocked(hq, now))
	} else if ss.closed || hold == 0 || ss.rxData || ss.hasData() {
		out = append(out, ss.answerLocked(hq, now))
	} else {
		ss.held = append(ss.held, hq)
		time.AfterFunc(hold, func() { ss.expire(hq) })
		// Bound held queries per session; answer the oldest.
		for len(ss.held) > 128 {
			out = append(out, ss.answerLocked(ss.held[0], now))
		}
	}
	out = append(out, ss.drainLocked(now)...)
	ss.mu.Unlock()
	ss.srv.send(out)
}

type sendItem struct {
	msg  []byte
	addr net.Addr
}

func (s *Server) send(items []sendItem) {
	for _, it := range items {
		s.pc.WriteTo(it.msg, it.addr)
	}
}

// answerLocked builds the answer to hq and removes it from the held list. Caller holds ss.mu.
func (ss *srvSession) answerLocked(hq *heldQuery, now time.Time) sendItem {
	it, _ := ss.answerPktLocked(hq, now)
	return it
}

func (ss *srvSession) answerPktLocked(hq *heldQuery, now time.Time) (sendItem, *sentPkt) {
	hq.answered = true
	for i, h := range ss.held {
		if h == hq {
			ss.held = append(ss.held[:i], ss.held[i+1:]...)
			break
		}
	}
	// Plaintext: hold applied (10ms units), backlog (packets queued), frames.
	budget := capacity(hq.q, hq.limit) - 2 - tagLen
	held := min(now.Sub(hq.at)/(10*time.Millisecond), 255)
	plain := []byte{byte(held), 0}
	pn, plain, _, pkt := ss.build(plain, budget-2, now, hq.upPN)
	if budget > 0 {
		plain[1] = byte(min(ss.pendingBytes()/budget, 255))
	}
	dbg("srv answer pn=%d up=%d plain=%x", pn, hq.upPN, plain)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(pn))
	sealed := ss.seal.seal(nil, downAD(hdr, hq.upPN), plain, pn)
	m := ss.seal.mask(sealed)
	payload := make([]byte, 0, 2+len(sealed))
	payload = append(payload, hdr[0]^m[0], hdr[1]^m[1])
	payload = append(payload, sealed...)
	return sendItem{msg: appendAnswer(make([]byte, 0, hq.limit), hq.q, rcodeOK, payload), addr: hq.addr}, pkt
}

// emptyAnswerLocked answers hq with a packet carrying no frames.
func (ss *srvSession) emptyAnswerLocked(hq *heldQuery, now time.Time) sendItem {
	hq.answered = true
	pn := ss.nextPN
	ss.nextPN++
	plain := make([]byte, 2+minPlain)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(pn))
	sealed := ss.seal.seal(nil, downAD(hdr, hq.upPN), plain, pn)
	m := ss.seal.mask(sealed)
	payload := append([]byte{hdr[0] ^ m[0], hdr[1] ^ m[1]}, sealed...)
	return sendItem{msg: appendAnswer(make([]byte, 0, 128), hq.q, rcodeOK, payload), addr: hq.addr}
}

// drainLocked answers held queries, oldest first, while there's data. Caller holds ss.mu.
func (ss *srvSession) drainLocked(now time.Time) []sendItem {
	var out []sendItem
	for len(ss.held) > 0 && ss.hasData() {
		it, pkt := ss.answerPktLocked(ss.held[0], now)
		out = append(out, it)
		// The queue just drained: send the tail again in another held poll.
		if pkt != nil && len(pkt.streams) > 0 && !ss.hasData() && len(ss.held) > 0 && ss.requeue(pkt) {
			it, _ := ss.answerPktLocked(ss.held[0], now)
			out = append(out, it)
		}
	}
	return out
}

func (ss *srvSession) flush() {
	ss.mu.Lock()
	out := ss.drainLocked(time.Now())
	ss.mu.Unlock()
	ss.srv.send(out)
}

func (ss *srvSession) expire(hq *heldQuery) {
	ss.mu.Lock()
	if hq.answered {
		ss.mu.Unlock()
		return
	}
	it := ss.answerLocked(hq, time.Now())
	ss.mu.Unlock()
	ss.srv.send([]sendItem{it})
}

// serveStream reads the destination from the stream's first bytes, dials it, and relays.
func (ss *srvSession) serveStream(st *stream) {
	c := &Conn{st: st}
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	addr, err := readAddr(c)
	dbg("srv stream %d addr=%q err=%v", st.id, addr, err)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	ctx, cancel := context.WithTimeout(ss.srv.ctx, 30*time.Second)
	up, err := ss.srv.cfg.Dial(ctx, "tcp", addr)
	cancel()
	if err != nil {
		ss.srv.cfg.Logger.Debug("dial failed", "addr", addr, "err", err)
		ss.mu.Lock()
		ss.queueCtrl(ctrl{typ: frReset, id: st.id, val: 1})
		st.abort(err)
		ss.maybeRemove(st)
		ss.mu.Unlock()
		ss.flush()
		return
	}
	relay(c, up)
}

// relay copies both ways and closes both ends when done.
// relay copies both ways and closes both ends when done. A clean EOF half-closes the other side;
// any error (a reset stream, a closed session, a failed destination) closes the destination so
// the opposite copy can't stay blocked on it.
func relay(c *Conn, up net.Conn) {
	done := make(chan struct{})
	go func() {
		if _, err := io.Copy(up, c); err != nil {
			up.Close()
		} else if cw, ok := up.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		close(done)
	}()
	if _, err := io.Copy(c, up); err != nil {
		up.Close()
		c.Close()
	} else {
		c.CloseWrite()
	}
	<-done
	up.Close()
	c.Close()
}

// PublicOnly is a net.Dialer Control function that refuses non-public destinations: loopback,
// private, link-local, CGNAT, reserved, and IPv6 forms that embed one (NAT64, 6to4, Teredo,
// IPv4-compatible). Anyone holding the (public) server key can open streams, so the server must
// not become a way into its own network. It checks the address actually dialed, after
// resolution, so DNS rebinding can't get around it. The default dialer uses it; a custom
// ServerConfig.Dial should too.
func PublicOnly(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if a := ap.Addr(); !isPublic(a) || isLocal(a) {
		return fmt.Errorf("soar: destination %s is not public", a)
	}
	return nil
}

// localAddrs caches this host's interface addresses: dialing our own public IP would reach
// services bound to all interfaces from inside, past firewalls that only filter outside traffic.
var localAddrs struct {
	sync.Mutex
	set map[netip.Addr]bool
	at  time.Time
}

func isLocal(a netip.Addr) bool {
	a = a.Unmap()
	localAddrs.Lock()
	defer localAddrs.Unlock()
	if localAddrs.set == nil || time.Since(localAddrs.at) > time.Minute {
		set := make(map[netip.Addr]bool)
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, ia := range addrs {
				if pfx, err := netip.ParsePrefix(ia.String()); err == nil {
					set[pfx.Addr().Unmap()] = true
				}
			}
		}
		localAddrs.set, localAddrs.at = set, time.Now()
	}
	return localAddrs.set[a]
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001::/32"),       // Teredo: tunnels to arbitrary IPv4
	netip.MustParsePrefix("fec0::/10"),       // site-local (deprecated)
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4-translated (SIIT)
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2001:2::/48"),     // benchmarking
	netip.MustParsePrefix("2001:10::/28"),    // ORCHID
}

func isPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	// NAT64 and 6to4 embed an IPv4 destination: judge that.
	if a.Is6() {
		b := a.As16()
		if netip.MustParsePrefix("64:ff9b::/96").Contains(a) {
			return isPublic(netip.AddrFrom4([4]byte(b[12:16])))
		}
		if netip.MustParsePrefix("2002::/16").Contains(a) {
			return isPublic(netip.AddrFrom4([4]byte(b[2:6])))
		}
	}
	return true
}

// readAddr reads a varint length and that many address bytes.
func readAddr(r io.Reader) (string, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	n := int(b[0])
	if n == 0 || n > 255 {
		return "", errors.New("soar: bad destination")
	}
	addr := make([]byte, n)
	if _, err := io.ReadFull(r, addr); err != nil {
		return "", err
	}
	return string(addr), nil
}

// sweep declares stale downstream packets lost and ends idle sessions.
func (s *Server) sweep() {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			s.mu.Lock()
			for _, ss := range s.sessions {
				ss.close(ErrClosed)
			}
			s.mu.Unlock()
			return
		case now := <-t.C:
			s.mu.Lock()
			for k, h := range s.hellos {
				if now.Sub(h.at) > time.Minute || s.sessions[h.sid] == nil {
					delete(s.hellos, k)
				}
			}
			sessions := make([]*srvSession, 0, len(s.sessions))
			for _, ss := range s.sessions {
				sessions = append(sessions, ss)
			}
			s.mu.Unlock()
			for _, ss := range sessions {
				ss.mu.Lock()
				for pn, p := range ss.sent {
					if now.Sub(p.at) > s.cfg.LossTimeout {
						dbg("srv TIMEOUT-LOSS down=%d up=%d streams=%d", pn, p.replyTo, len(p.streams))
						ss.declareLost(pn)
					}
				}
				idle := now.Sub(ss.lastSeen) > s.cfg.IdleTimeout || ss.closed ||
					(!ss.used.Load() && now.Sub(ss.created) > 15*time.Second)
				out := ss.drainLocked(now)
				ss.mu.Unlock()
				s.send(out)
				if idle {
					ss.close(ErrClosed)
					s.mu.Lock()
					delete(s.sessions, ss.sid)
					s.mu.Unlock()
				}
			}
		}
	}
}

var debugOn = os.Getenv("SOAR_DEBUG") != ""

func dbg(f string, a ...any) {
	if debugOn {
		fmt.Fprintf(os.Stderr, time.Now().Format("05.000 ")+f+"\n", a...)
	}
}
