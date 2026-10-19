package soar

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// helloTo sends a hello under z (which may carry an account label) and returns the answer's
// rcode, or -1 if nothing came back. It talks to the server directly, so what it measures is
// what the server decided about the hello itself.
func helloTo(t *testing.T, srv string, z zone) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr, err := net.ResolveUDPAddr("udp", srv)
	if err != nil {
		t.Fatal(err)
	}
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	payload := append([]byte{0, 0}, eph.PublicKey().Bytes()...)
	if _, err := pc.WriteTo(appendQuery(nil, 0x4242, payload, z, typeTXT, 1232), addr); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || n < hdrLen {
		return -1
	}
	return int(buf[3] & 0x0F)
}

// labelled is the zone a client is configured with when the server identifies by label: the
// account's label, then the server's own zone.
func labelled(t *testing.T, label string) zone {
	t.Helper()
	z, err := parseZone(label + "." + testZone)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestLabelIdentityReachesDial(t *testing.T) {
	type account struct{ quota int }
	mine := &account{quota: 7}
	var got atomic.Pointer[Identity]
	srv, pub := startServerWith(t, ServerConfig{
		IdentifyByLabel: true,
		VerifyLabel: func(l string) (any, bool) {
			if l != "member01" {
				return nil, false
			}
			return mine, true
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if id, ok := IdentityFromContext(ctx); ok {
				got.Store(id)
			}
			return loopbackDial(ctx, network, addr)
		},
	})
	origin := startOrigin(t)
	c, err := NewClient(Config{Zone: "member01." + testZone, ServerKey: pub, Resolvers: []string{srv}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fetch(t, c, origin, 1000)
	id := got.Load()
	if id == nil {
		t.Fatal("Dial saw no identity")
	}
	if id.Label != "member01" {
		t.Fatalf("label %q", id.Label)
	}
	if id.Account != any(mine) {
		t.Fatalf("account %v, want the one VerifyLabel returned", id.Account)
	}
	if id.Sealed {
		t.Fatal("a label identity must not claim to be sealed: the name is not authenticated")
	}
}

func TestUnknownLabelIsRefusedBeforeTheHandshake(t *testing.T) {
	var asked atomic.Int64
	dialed := make(chan struct{}, 1)
	srv, _ := startServerWith(t, ServerConfig{
		IdentifyByLabel: true,
		VerifyLabel: func(l string) (any, bool) {
			asked.Add(1)
			return nil, l == "known"
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			select {
			case dialed <- struct{}{}:
			default:
			}
			return loopbackDial(ctx, network, addr)
		},
	})
	if rc := helloTo(t, srv, labelled(t, "stranger")); rc != rcodeRefused {
		t.Fatalf("unknown label: rcode %d, want REFUSED (%d)", rc, rcodeRefused)
	}
	if rc := helloTo(t, srv, labelled(t, "known")); rc != rcodeOK {
		t.Fatalf("known label: rcode %d, want NOERROR", rc)
	}
	if n := asked.Load(); n != 2 {
		t.Fatalf("VerifyLabel called %d times, want one per hello", n)
	}
	select {
	case <-dialed:
		t.Fatal("a refused hello reached Dial")
	default:
	}
}

func TestMalformedLabelIsRefused(t *testing.T) {
	srv, _ := startServerWith(t, ServerConfig{
		IdentifyByLabel: true,
		VerifyLabel:     func(string) (any, bool) { return nil, true },
		Dial:            loopbackDial,
	})
	// A DNS label may hold any 63 bytes. One that is not an unambiguous, case-insensitive
	// token has no business reaching an account lookup, a log line or a backend credential.
	for _, label := range []string{"member!01", "mem*ber", "mem$ber", "esc\x1b[31m", "sp ace", "new\nline"} {
		if rc := helloTo(t, srv, withLabel(t, label)); rc != rcodeRefused {
			t.Errorf("label %q: rcode %d, want REFUSED", label, rc)
		}
	}
}

// withLabel builds the zone a client would send for label, whatever it holds: parseZone refuses
// anything but printable ASCII, so the label goes into the wire form directly.
func withLabel(t *testing.T, label string) zone {
	t.Helper()
	z, err := parseZone(testZone)
	if err != nil {
		t.Fatal(err)
	}
	z.wire = append(append([]byte{byte(len(label))}, label...), z.wire...)
	z.text = label + "." + z.text
	return z
}

func TestLabelCaseIsFolded(t *testing.T) {
	// A resolver may randomize the case of a name on the way to the server (0x20 encoding),
	// which is why the base32 payload decodes case-insensitively. The label must fold too, or
	// such a resolver would knock an account offline.
	var seen atomic.Value
	srv, _ := startServerWith(t, ServerConfig{
		IdentifyByLabel: true,
		VerifyLabel: func(l string) (any, bool) {
			seen.Store(l)
			return nil, true
		},
		Dial: loopbackDial,
	})
	// parseZone folds, so the mixed-case label goes into the wire form directly.
	if rc := helloTo(t, srv, withLabel(t, "MeMbEr01")); rc != rcodeOK {
		t.Fatalf("mixed-case label: rcode %d, want NOERROR", rc)
	}
	if got := seen.Load(); got != "member01" {
		t.Fatalf("VerifyLabel saw %q, want the folded label", got)
	}
}

// relabeller forwards queries to the server, rewriting the account label of every nth data
// query (never the hello) to victim. It stands for a resolver on the path, which is exactly who
// can do this: the query name is not covered by the handshake.
//
// Only some queries are rewritten because the server echoes the question it was asked and the
// client checks it (see onAnswer), so a rewritten query's answer is discarded as unmatched and
// the data on it has to be sent again. Rewriting everything would just stall the session - any
// resolver can do that by dropping queries - and the question here is not whether a resolver
// can disrupt an account, but whether it can get one charged to another.
func relabeller(t *testing.T, server, victim string, nth int) string {
	t.Helper()
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close() })
	back, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { back.Close() })
	saddr, _ := net.ResolveUDPAddr("udp", server)
	var mu sync.Mutex
	var client net.Addr
	seen := 0
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
			msg := buf[:n]
			// Overwrite the account label in place - same length, so nothing else moves. The
			// hello is left alone: the point is a session that handshook under one account and
			// is then claimed by another, which is what an on-path resolver can try.
			if i := labelOffset(msg, len(victim)); i > 0 && !isHello(msg, i) {
				if seen++; seen%nth == 0 {
					copy(msg[i:], victim)
				}
			}
			back.WriteTo(msg, saddr)
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
			if to != nil {
				front.WriteTo(buf[:n], to)
			}
		}
	}()
	return front.LocalAddr().String()
}

// isHello reports whether the query whose account label starts at i carries session id 0.
func isHello(msg []byte, i int) bool {
	var enc []byte
	for j := hdrLen; j < i-1; {
		l := int(msg[j])
		if l == 0 || l > maxLabel || j+1+l > len(msg) {
			break
		}
		enc = append(enc, msg[j+1:j+1+l]...)
		j += 1 + l
	}
	p, err := b32Decode(nil, enc)
	return err == nil && len(p) >= 2 && p[0] == 0 && p[1] == 0
}

// labelOffset returns where the label of length n directly above testZone starts in msg, or 0.
func labelOffset(msg []byte, n int) int {
	i := hdrLen
	var starts []int
	var lens []int
	for i < len(msg) {
		l := int(msg[i])
		if l == 0 || l > maxLabel || i+1+l > len(msg) {
			break
		}
		starts = append(starts, i+1)
		lens = append(lens, l)
		i += 1 + l
	}
	zl := len(strings.Split(testZone, "."))
	if len(starts) < zl+1 {
		return 0
	}
	k := len(starts) - zl - 1
	if lens[k] != n {
		return 0
	}
	return starts[k]
}

func TestLabelIsPinnedToTheHandshake(t *testing.T) {
	var labels sync.Map
	mismatches := &countHandler{want: "does not match"}
	srv, pub := startServerWith(t, ServerConfig{
		IdentifyByLabel: true,
		VerifyLabel:     func(string) (any, bool) { return nil, true },
		Logger:          slog.New(mismatches),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			labels.Store(UserFromContext(ctx), true)
			return loopbackDial(ctx, network, addr)
		},
	})
	origin := startOrigin(t)
	// One data query in three arrives claiming "victim01"; the hello says "member01".
	res := relabeller(t, srv, "victim01", 3)
	c, err := NewClient(Config{Zone: "member01." + testZone, ServerKey: pub, Resolvers: []string{res}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fetch(t, c, origin, 32<<10)
	if _, bad := labels.Load("victim01"); bad {
		t.Fatal("a rewritten query label re-attributed a live session")
	}
	if _, ok := labels.Load("member01"); !ok {
		t.Fatal("the session lost the label it handshook with")
	}
	if n := mismatches.n.Load(); n == 0 {
		t.Fatal("the server did not report the rewritten labels")
	} else {
		t.Logf("%d rewritten labels seen and ignored", n)
	}
}

// countHandler counts log records whose message contains want.
type countHandler struct {
	want string
	n    atomic.Int64
}

func (h *countHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countHandler) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.want) {
		h.n.Add(1)
	}
	return nil
}
func (h *countHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countHandler) WithGroup(string) slog.Handler      { return h }

func TestMaxSessionsPerAccount(t *testing.T) {
	srv, _ := startServerWith(t, ServerConfig{
		IdentifyByLabel:       true,
		VerifyLabel:           func(string) (any, bool) { return nil, true },
		MaxSessionsPerAccount: 2,
		Dial:                  loopbackDial,
	})
	z := labelled(t, "member01")
	for i := range 2 {
		if rc := helloTo(t, srv, z); rc != rcodeOK {
			t.Fatalf("hello %d: rcode %d, want NOERROR", i+1, rc)
		}
	}
	if rc := helloTo(t, srv, z); rc != rcodeRefused {
		t.Fatalf("hello past the cap: rcode %d, want REFUSED", rc)
	}
	// A different account is unaffected: the cap is per account, not a global brake.
	if rc := helloTo(t, srv, labelled(t, "member02")); rc != rcodeOK {
		t.Fatalf("another account: rcode %d, want NOERROR", rc)
	}
}

// --- sealed identity ---

func testIdentity(key byte) *ClientIdentity {
	id := &ClientIdentity{Key: make([]byte, 32)}
	for i := range id.Key {
		id.Key[i] = key
	}
	id.KeyID[0] = key
	return id
}

func TestSealedIdentityReachesDial(t *testing.T) {
	want := testIdentity(9)
	type account struct{ name string }
	mine := &account{name: "member01"}
	var got atomic.Pointer[Identity]
	srv, pub := startServerWith(t, ServerConfig{
		VerifyClient: func(keyID [IdentKeyLen]byte) ([]byte, any, bool) {
			if keyID != want.KeyID {
				return nil, nil, false
			}
			return want.Key, mine, true
		},
		RequireIdentity: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if id, ok := IdentityFromContext(ctx); ok {
				got.Store(id)
			}
			return loopbackDial(ctx, network, addr)
		},
	})
	origin := startOrigin(t)
	c, err := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}, Identity: want})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fetch(t, c, origin, 4000)
	id := got.Load()
	if id == nil {
		t.Fatal("Dial saw no identity")
	}
	if !id.Sealed {
		t.Fatal("identity not marked sealed")
	}
	if id.KeyID != want.KeyID || id.Account != any(mine) {
		t.Fatalf("identity %+v", id)
	}
}

func TestSealedIdentityIsNotInTheQueryName(t *testing.T) {
	// The whole point: a resolver that logs every name learns nothing about the account.
	id := testIdentity(3)
	srv, pub := startServerWith(t, ServerConfig{
		VerifyClient: func([IdentKeyLen]byte) ([]byte, any, bool) { return id.Key, nil, true },
		Dial:         loopbackDial,
	})
	origin := startOrigin(t)
	var names []string
	var mu sync.Mutex
	res := nameLogger(t, srv, func(n string) { mu.Lock(); names = append(names, n); mu.Unlock() })
	c, err := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{res}, Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fetch(t, c, origin, 4000)
	mu.Lock()
	defer mu.Unlock()
	if len(names) == 0 {
		t.Fatal("no queries observed")
	}
	// Nothing stable about the account may show up: not the key id, not the proof.
	for _, n := range names {
		for _, secret := range []string{"03", string(id.KeyID[:]), string(id.Key)} {
			if strings.Contains(n, secret) && len(secret) > 2 {
				t.Fatalf("query name %q carries the credential", n)
			}
		}
	}
	// And every name is unique noise: no constant selector for an account.
	first := names[0]
	same := 0
	for _, n := range names {
		if n == first {
			same++
		}
	}
	if same > 2 { // a retransmission may repeat one
		t.Fatalf("%d of %d queries share a name: that is a selector", same, len(names))
	}
}

// nameLogger forwards queries and reports each QNAME in presentation form.
func nameLogger(t *testing.T, server string, log func(string)) string {
	t.Helper()
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
			var parts []string
			for i := hdrLen; i < len(msg); {
				l := int(msg[i])
				if l == 0 || l > maxLabel || i+1+l > len(msg) {
					break
				}
				parts = append(parts, string(msg[i+1:i+1+l]))
				i += 1 + l
			}
			log(strings.Join(parts, "."))
			back, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return
			}
			back.WriteTo(msg, saddr)
			go func() {
				defer back.Close()
				rb := make([]byte, 4096)
				back.SetReadDeadline(time.Now().Add(5 * time.Second))
				if m, _, err := back.ReadFrom(rb); err == nil {
					front.WriteTo(rb[:m], from)
				}
			}()
		}
	}()
	return front.LocalAddr().String()
}

func TestSealedProofIsBoundToItsSession(t *testing.T) {
	id := testIdentity(5)
	eph1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	eph2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	srvEph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	tr1 := transcript(eph1.PublicKey().Bytes(), srvEph.PublicKey().Bytes(), 0x1111)
	proof := identProof(id.Key, id.KeyID, tr1)
	// The same credential in another session, with another ephemeral key or another session id,
	// produces a different proof: a captured one authenticates nothing else.
	for name, tr := range map[string][]byte{
		"another client key": transcript(eph2.PublicKey().Bytes(), srvEph.PublicKey().Bytes(), 0x1111),
		"another session id": transcript(eph1.PublicKey().Bytes(), srvEph.PublicKey().Bytes(), 0x2222),
	} {
		if string(identProof(id.Key, id.KeyID, tr)) == string(proof) {
			t.Errorf("%s: the proof replayed", name)
		}
	}
	// Nor under another account's id, which the proof also covers.
	other := id.KeyID
	other[0] ^= 1
	if string(identProof(id.Key, other, tr1)) == string(proof) {
		t.Error("the proof carried over to another key id")
	}
}

func TestSealedIdentityRejectedEndsTheSession(t *testing.T) {
	// The client proves an account the server does not know: no stream, and the session goes.
	dialed := make(chan struct{}, 1)
	srv, pub := startServerWith(t, ServerConfig{
		VerifyClient:    func([IdentKeyLen]byte) ([]byte, any, bool) { return nil, nil, false },
		RequireIdentity: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed <- struct{}{}
			return loopbackDial(ctx, network, addr)
		},
	})
	origin := startOrigin(t)
	c, err := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}, Identity: testIdentity(1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := tryStream(t, c, origin); err == nil {
		t.Fatal("a rejected identity still carried traffic")
	}
	select {
	case <-dialed:
		t.Fatal("a rejected identity reached Dial")
	default:
	}
}

// tryStream opens a stream and uses it. DialContext does not wait for the server to confirm the
// destination (that is what OPENED is for, and only a caller that needs it waits), so a refusal
// shows up on the first read or write.
func tryStream(t *testing.T, c *Client, origin string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", origin)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "16\n"); err != nil {
		return err
	}
	_, err = io.ReadFull(conn, make([]byte, 16))
	return err
}

func TestRequireIdentityRefusesAnUnidentifiedClient(t *testing.T) {
	dialed := make(chan struct{}, 1)
	srv, pub := startServerWith(t, ServerConfig{
		VerifyClient:    func([IdentKeyLen]byte) ([]byte, any, bool) { return nil, nil, false },
		RequireIdentity: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed <- struct{}{}
			return loopbackDial(ctx, network, addr)
		},
	})
	origin := startOrigin(t)
	// An ordinary client: it handshakes, then asks for a stream without identifying itself.
	c, err := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := tryStream(t, c, origin); err == nil {
		t.Fatal("an unidentified client carried traffic")
	}
	select {
	case <-dialed:
		t.Fatal("an unidentified client reached Dial")
	default:
	}
}

func TestIdentityOffBehavesLikeUpstream(t *testing.T) {
	// A server that sets neither mode must treat the whole name as payload, and a client that
	// sets no identity must send no extension frame.
	srv, pub := startServerWith(t, ServerConfig{Dial: loopbackDial})
	origin := startOrigin(t)
	c, err := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialContext(context.Background(), "tcp", origin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "16\n"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 16)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pattern(16)) {
		t.Fatal("payload mismatch")
	}
}

func TestIdentFrameFitsTheSafeQueryName(t *testing.T) {
	// Frames are never split across packets, so the identity has to fit the smallest packet a
	// path ever sends: the one at SafeQName. This is why the proof is a truncated MAC and not
	// an Ed25519 key and signature, which would be 96 bytes on their own.
	z, err := parseZone(testZone)
	if err != nil {
		t.Fatal(err)
	}
	budget := z.maxPayload(101) - 4 - tagLen - 1
	if identFrameLen > budget {
		t.Fatalf("IDENT is %d bytes, budget at a 101-character name is %d", identFrameLen, budget)
	}
	// And a client is told up front when its zone leaves no room, rather than stalling later.
	long := strings.Repeat("z", 30) + ".example.com"
	_, err = NewClient(Config{Zone: long, ServerKey: mustPub(t), Resolvers: []string{"127.0.0.1:53"},
		SafeQName: 101, Identity: testIdentity(2)})
	if err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("a zone with no room for an identity was accepted: %v", err)
	}
}

func mustPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestClientIdentityNeedsAKey(t *testing.T) {
	_, err := NewClient(Config{Zone: testZone, ServerKey: mustPub(t), Resolvers: []string{"127.0.0.1:53"},
		Identity: &ClientIdentity{}})
	if err == nil {
		t.Fatal("an identity with no key was accepted")
	}
}

// --- the extension frame itself ---

func TestIdentFrameRoundTrips(t *testing.T) {
	id := testIdentity(7)
	tr := transcript(make([]byte, pubLen), make([]byte, pubLen), 1)
	want := identProof(id.Key, id.KeyID, tr)
	b := appendIdent(nil, id.KeyID, want)
	if len(b) != identFrameLen {
		t.Fatalf("frame is %d bytes, identFrameLen says %d", len(b), identFrameLen)
	}
	var seen int
	err := parseFrames(b, func(f *frame) error {
		seen++
		if f.typ != frExt || f.val != extIdent {
			t.Fatalf("frame type %#x sub-type %d", f.typ, f.val)
		}
		keyID, proof, ok := parseIdent(f.data)
		if !ok || keyID != id.KeyID || string(proof) != string(want) {
			t.Fatalf("decoded %x %x ok=%v", keyID, proof, ok)
		}
		return nil
	})
	if err != nil || seen != 1 {
		t.Fatalf("err %v, frames %d", err, seen)
	}
}
