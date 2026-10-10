package seep

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305" //nolint:staticcheck // needed for a truncated-tag AEAD
)

const (
	tagLen    = 8 // truncated Poly1305 tag: a forgery succeeds with p=2^-64 per attempt
	sampleLen = 12
	minPlain  = sampleLen - tagLen // plaintext floor so header protection has a full sample
	pubLen    = 32
	sigLen    = ed25519.SignatureSize
	// helloReplyLen is serverEph || sid || signature.
	helloReplyLen = pubLen + 2 + sigLen

	sigContext = "seep v1 hello"
	kdfLabel   = "seep v1 "
)

var (
	errAuth         = errors.New("seep: packet authentication failed")
	errBadSignature = errors.New("seep: server signature verification failed")
)

// packetCipher seals one direction's packets: ChaCha20-Poly1305 (RFC 8439) with the tag truncated
// to 8 bytes, a per-packet nonce derived from the packet number, and QUIC-style protection of the
// truncated packet number so it doesn't appear as a counter on the wire.
type packetCipher struct {
	key [32]byte
	iv  [12]byte
	hp  [32]byte
}

func (c *packetCipher) nonce(pn uint64) []byte {
	n := c.iv
	for i := range 8 {
		n[4+i] ^= byte(pn >> (56 - 8*i))
	}
	return n[:]
}

// seal appends the encryption of plain and its tag to dst.
func (c *packetCipher) seal(dst, ad, plain []byte, pn uint64) []byte {
	s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], c.nonce(pn))
	start := len(dst)
	dst = append(dst, plain...)
	ct := dst[start:]
	// The Poly1305 key is block 0; the payload starts at block 1.
	var block0 [64]byte
	s.XORKeyStream(block0[:], block0[:])
	s.XORKeyStream(ct, ct)
	return append(dst, c.tagFrom(block0[:32], ad, ct)...)
}

func (c *packetCipher) tagFrom(polyKey, ad, ct []byte) []byte {
	var k [32]byte
	copy(k[:], polyKey)
	m := poly1305.New(&k)
	var pad [16]byte
	m.Write(ad)
	m.Write(pad[:(16-len(ad)%16)%16])
	m.Write(ct)
	m.Write(pad[:(16-len(ct)%16)%16])
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[:8], uint64(len(ad)))
	binary.LittleEndian.PutUint64(lens[8:], uint64(len(ct)))
	m.Write(lens[:])
	return m.Sum(nil)[:tagLen]
}

// open authenticates and decrypts ct||tag, returning a new plaintext slice.
func (c *packetCipher) open(ad, sealed []byte, pn uint64) ([]byte, error) {
	if len(sealed) < tagLen {
		return nil, errAuth
	}
	ct, tag := sealed[:len(sealed)-tagLen], sealed[len(sealed)-tagLen:]
	s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], c.nonce(pn))
	var block0 [64]byte
	s.XORKeyStream(block0[:], block0[:])
	if subtle.ConstantTimeCompare(c.tagFrom(block0[:32], ad, ct), tag) != 1 {
		return nil, errAuth
	}
	plain := make([]byte, len(ct))
	s.XORKeyStream(plain, ct)
	return plain, nil
}

// mask returns the 2-byte packet-number mask for a ciphertext sample.
func (c *packetCipher) mask(sample []byte) [2]byte {
	s, _ := chacha20.NewUnauthenticatedCipher(c.hp[:], sample[:sampleLen])
	var m [2]byte
	s.XORKeyStream(m[:], m[:])
	return m
}

func newCipher(prk []byte, dir string) (*packetCipher, error) {
	c := &packetCipher{}
	for _, f := range []struct {
		dst   []byte
		label string
	}{{c.key[:], "key"}, {c.iv[:], "iv"}, {c.hp[:], "hp"}} {
		b, err := hkdf.Expand(sha256.New, prk, kdfLabel+dir+" "+f.label, len(f.dst))
		if err != nil {
			return nil, err
		}
		copy(f.dst, b)
	}
	return c, nil
}

// sessionCiphers derives both directions' ciphers from the ephemeral-ephemeral secret, salted with
// the handshake transcript.
func sessionCiphers(ee, transcript []byte) (up, down *packetCipher, err error) {
	prk, err := hkdf.Extract(sha256.New, ee, transcript)
	if err != nil {
		return nil, nil, err
	}
	if up, err = newCipher(prk, "up"); err != nil {
		return nil, nil, err
	}
	down, err = newCipher(prk, "down")
	return up, down, err
}

func transcript(clientEph, serverEph []byte, sid uint16) []byte {
	t := make([]byte, 0, len(sigContext)+2*pubLen+2)
	t = append(t, sigContext...)
	t = append(t, clientEph...)
	t = append(t, serverEph...)
	return binary.BigEndian.AppendUint16(t, sid)
}

// serverHello answers a client's ephemeral key: it returns the reply bytes and the session ciphers.
func serverHello(priv ed25519.PrivateKey, clientEph []byte, sid uint16) (reply []byte, up, down *packetCipher, err error) {
	cpub, err := ecdh.X25519().NewPublicKey(clientEph)
	if err != nil {
		return nil, nil, nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	ee, err := eph.ECDH(cpub)
	if err != nil {
		return nil, nil, nil, err
	}
	tr := transcript(clientEph, eph.PublicKey().Bytes(), sid)
	if up, down, err = sessionCiphers(ee, tr); err != nil {
		return nil, nil, nil, err
	}
	reply = append(eph.PublicKey().Bytes(), byte(sid>>8), byte(sid))
	return append(reply, ed25519.Sign(priv, tr)...), up, down, nil
}

// clientFinish verifies the server's hello reply and derives the session.
func clientFinish(pub ed25519.PublicKey, eph *ecdh.PrivateKey, reply []byte) (sid uint16, up, down *packetCipher, err error) {
	if len(reply) < helloReplyLen {
		return 0, nil, nil, errBadSignature
	}
	seph := reply[:pubLen]
	sid = binary.BigEndian.Uint16(reply[pubLen:])
	tr := transcript(eph.PublicKey().Bytes(), seph, sid)
	if !ed25519.Verify(pub, tr, reply[pubLen+2:helloReplyLen]) {
		return 0, nil, nil, errBadSignature
	}
	spub, err := ecdh.X25519().NewPublicKey(seph)
	if err != nil {
		return 0, nil, nil, err
	}
	ee, err := eph.ECDH(spub)
	if err != nil {
		return 0, nil, nil, err
	}
	up, down, err = sessionCiphers(ee, tr)
	return sid, up, down, err
}
