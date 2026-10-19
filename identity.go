package soar

// Client identity, for servers run for a known set of accounts.
//
// Soar itself has no notion of a client: one server key is shared by everyone who holds it, and
// that is the right default for a last-resort bootstrap transport where the server is a public
// good and anonymity is a feature. A server run for accounts it meters needs the opposite, and
// without help from the protocol it has to invent identity outside it.
//
// Two ways are offered here. Both are optional and both are off by default, so a server that
// sets neither behaves exactly as upstream.
//
//	Label  — the label directly above the zone names the account
//	         (<account>.tunnel.example.com). The client needs no change at all: it is configured
//	         with a longer zone and everything it encodes stays above the label. The price is
//	         that the label travels in the query name, in cleartext, past every recursive
//	         resolver on the path. It is therefore a bearer credential and a stable selector,
//	         and no amount of encrypting it helps: the client sends one fixed zone verbatim on
//	         every query, so the label is necessarily constant, and a constant ciphertext is as
//	         copyable as a constant hash.
//
//	Sealed — an IDENT frame in the first upstream packet, carrying a key id and a MAC over the
//	         handshake transcript (§4.2). It is inside seal(...), so a resolver sees ciphertext,
//	         and the transcript holds both ephemeral public keys and the session id, so a
//	         captured proof authenticates nothing else. Both ends must opt in: the frame rides
//	         in the EXT frame type, which upstream does not know and would treat as an error
//	         (SPEC §6), so a client only ever sends it to a server that asked for it.
//
// Label mode is what keeps today's clients working. Sealed mode is what a client should use when
// it can be changed.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// errIdentity ends a session whose client claimed an identity it could not prove.
var errIdentity = errors.New("soar: client identity rejected")

// IdentKeyLen is the length of a sealed identity's key id, which names the account. The id is
// inside the sealed payload, so it reveals nothing on the wire; 8 bytes is room for far more
// accounts than a server can hold sessions for.
const IdentKeyLen = 8

const (
	// identContext domain-separates a client's proof from the server's own signatures over the
	// same transcript (sigContext, unknownContext).
	identContext = "soar v1 client auth"
	// identTagLen is the truncated HMAC-SHA256 over the transcript. 16 bytes is a 2^-128
	// forgery probability, and keeps the whole frame inside the upstream budget: some networks
	// drop names longer than ~101 characters, which leaves about 50 payload bytes per query
	// (README, "Small upstream overhead"), and an Ed25519 public key and signature alone would
	// be 96. See identFrameLen.
	identTagLen = 16
	// identFrameLen is the whole frame: EXT type, sub-type, length, key id, tag.
	identFrameLen = 3 + IdentKeyLen + identTagLen
)

// identProof is what a client sends and a server recomputes: HMAC-SHA256(key, identContext ||
// keyID || transcript), truncated. The key id is covered too, so a proof cannot be re-presented
// under another account's id.
func identProof(key []byte, keyID [IdentKeyLen]byte, tr []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(identContext))
	m.Write(keyID[:])
	m.Write(tr)
	return m.Sum(nil)[:identTagLen]
}

// appendIdent encodes an IDENT frame as an extension frame.
func appendIdent(b []byte, keyID [IdentKeyLen]byte, proof []byte) []byte {
	b = append(b, frExt)
	b = appendVarint(b, extIdent)
	b = appendVarint(b, uint64(IdentKeyLen+len(proof)))
	b = append(b, keyID[:]...)
	return append(b, proof...)
}

// parseIdent reads an IDENT extension frame's body.
func parseIdent(body []byte) (keyID [IdentKeyLen]byte, proof []byte, ok bool) {
	if len(body) != IdentKeyLen+identTagLen {
		return keyID, nil, false
	}
	copy(keyID[:], body)
	return keyID, body[IdentKeyLen:], true
}

// Identity is who the client of a session is, as the server established it. It reaches
// ServerConfig.Dial through the context; see IdentityFromContext.
type Identity struct {
	// Label is the label above the zone, when IdentifyByLabel is set. Lower-cased: resolvers
	// may randomize the case of a name on its way to us (0x20 encoding), so the bytes that
	// arrive are not necessarily the bytes the client was configured with.
	Label string
	// KeyID names the account in sealed mode, and is zero in label mode.
	KeyID [IdentKeyLen]byte
	// Sealed reports that the identity was proved against the handshake transcript rather than
	// read from the query name. Only a sealed identity is safe against an on-path resolver:
	// a label can be rewritten by anyone who carries the query.
	Sealed bool
	// Account is whatever VerifyLabel or VerifyClient returned, so a server can carry its own
	// account object (a quota, a credential, a rate limiter) straight to Dial.
	Account any
}

// key identifies the account for per-account accounting (MaxSessionsPerAccount).
func (id *Identity) key() string {
	if id.Sealed {
		return "k:" + hex.EncodeToString(id.KeyID[:])
	}
	return "l:" + id.Label
}

type identityContextKey struct{}

// IdentityFromContext returns the identity of the session a Dial belongs to, when the server
// established one.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityContextKey{}).(*Identity)
	return id, ok
}

// UserFromContext returns the account label of the session a Dial belongs to, or "" when the
// server does not identify clients. It is shorthand for IdentityFromContext().Label.
func UserFromContext(ctx context.Context) string {
	if id, ok := IdentityFromContext(ctx); ok {
		return id.Label
	}
	return ""
}

// validLabel reports whether l is usable as an account label, and returns it folded to lower
// case. A label arrives attacker-controlled: a DNS label may hold any 63 bytes, and it ends up
// in a server's logs, its account lookups and whatever credential it hands the account's
// backend. Restricting it to an unambiguous, printable, case-insensitive set keeps it from
// carrying anything else (newlines and terminal escapes into a log, separators into a lookup).
func validLabel(l []byte) (string, bool) {
	if len(l) == 0 || len(l) > maxLabel {
		return "", false
	}
	var buf [maxLabel]byte
	b := buf[:len(l)]
	for i, c := range l {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return "", false
		}
		b[i] = c
	}
	return string(b), true
}

// setIdentity attaches id to the session and builds the context every stream of that session
// dials with, once. Caller holds ss.mu, or holds the session before it is reachable.
func (ss *srvSession) setIdentity(id *Identity) {
	ss.id = id
	ss.dialCtx = context.WithValue(ss.srv.ctx, identityContextKey{}, id)
}

// takeAccount counts one more live session against id's account and reports whether the account
// is still within MaxSessionsPerAccount. One account - or one copied label - can then not fill
// MaxSessions and lock everyone else out.
func (ss *srvSession) takeAccount(id *Identity) bool {
	m := ss.srv.cfg.MaxSessionsPerAccount
	if m <= 0 {
		return true
	}
	k := id.key()
	s := ss.srv
	s.acctMu.Lock()
	if s.perAccount[k] >= m {
		s.acctMu.Unlock()
		return false
	}
	s.perAccount[k]++
	s.acctMu.Unlock()
	if old := ss.counted.Swap(&k); old != nil {
		s.dropAccount(*old) // a sealed identity replacing the label's
	}
	return true
}

// releaseAccount gives back the session's count. Called wherever a session leaves the server's
// table; the swap makes it exactly once, however often it is called.
func (ss *srvSession) releaseAccount() {
	if k := ss.counted.Swap(nil); k != nil {
		ss.srv.dropAccount(*k)
	}
}

func (s *Server) dropAccount(k string) {
	s.acctMu.Lock()
	if n := s.perAccount[k] - 1; n > 0 {
		s.perAccount[k] = n
	} else {
		delete(s.perAccount, k)
	}
	s.acctMu.Unlock()
}

// onExtFrame handles an extension frame. Caller holds ss.mu (session.receive).
func (ss *srvSession) onExtFrame(sub uint64, body []byte) error {
	if sub != extIdent {
		return nil // a sub-type this server does not implement: skipped, not fatal
	}
	cfg := &ss.srv.cfg
	if cfg.VerifyClient == nil {
		return nil
	}
	if ss.id != nil && ss.id.Sealed {
		// Already identified. A repeat is a retransmission; anything else is a client bug or
		// an attempt to re-attribute a live session. Neither may change the identity.
		return nil
	}
	keyID, proof, ok := parseIdent(body)
	if !ok {
		return errFrame
	}
	key, acct, ok := cfg.VerifyClient(keyID)
	// Only the client that completed this handshake can produce a frame inside the session's
	// cipher at all, so a proof that does not check out is the client's own doing: end the
	// session rather than keep serving one that believes it is authenticated.
	if !ok || !hmac.Equal(identProof(key, keyID, ss.tr), proof) {
		cfg.Logger.Debug("client identity rejected", "key", hex.EncodeToString(keyID[:]))
		return errIdentity
	}
	id := &Identity{KeyID: keyID, Sealed: true, Account: acct, Label: ss.label}
	if !ss.takeAccount(id) {
		return errIdentity
	}
	ss.setIdentity(id)
	cfg.Logger.Debug("client identified", "key", hex.EncodeToString(keyID[:]))
	return nil
}
