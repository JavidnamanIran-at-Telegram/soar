package seep

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestRangeSet(t *testing.T) {
	var s rangeSet
	s.add(5, 10)
	s.add(0, 3)
	s.add(3, 5)
	if len(s) != 1 || s[0] != (span{0, 10}) {
		t.Fatalf("merge: %v", s)
	}
	s.add(20, 30)
	s.remove(2, 25)
	if len(s) != 2 || s[0] != (span{0, 2}) || s[1] != (span{25, 30}) {
		t.Fatalf("remove: %v", s)
	}
	if !s.contains(1) || s.contains(2) || !s.contains(29) {
		t.Fatalf("contains: %v", s)
	}
	if s.coveredFrom(0) != 2 {
		t.Fatal("coveredFrom")
	}
}

func TestFramesRoundTrip(t *testing.T) {
	acks := rangeSet{{1, 3}, {5, 6}, {9, 20}}
	var b []byte
	b = appendAck(b, acks)
	b = appendLost(b, []uint64{40, 7, 6, 0})
	b = ctrl{typ: frMaxStream, id: 3, val: 1 << 20}.appendTo(b)
	b = appendStream(b, 2, 100, []byte("hello"), false, false)
	b = appendStream(b, 7, 0, []byte("tail"), true, true)
	var got []frame
	if err := parseFrames(b, func(f *frame) error { got = append(got, *f); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d frames", len(got))
	}
	if len(got[0].ranges) != 3 || got[0].ranges[0] != acks[0] || got[0].ranges[2] != acks[2] {
		t.Fatalf("ack: %v", got[0].ranges)
	}
	if l := got[1].lost; len(l) != 4 || l[0] != 40 || l[3] != 0 {
		t.Fatalf("lost: %v", l)
	}
	if got[2].id != 3 || got[2].val != 1<<20 {
		t.Fatal("maxStream")
	}
	if got[3].id != 2 || got[3].off != 100 || string(got[3].data) != "hello" || got[3].fin {
		t.Fatal("stream")
	}
	if got[4].id != 7 || string(got[4].data) != "tail" || !got[4].fin {
		t.Fatal("last stream")
	}
}

func TestHandshakeAndPacket(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	reply, sUp, sDown, err := serverHello(priv, eph.PublicKey().Bytes(), 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	sid, cUp, cDown, err := clientFinish(pub, eph, reply)
	if err != nil || sid != 0x1234 {
		t.Fatal(sid, err)
	}
	ad := []byte{1, 2, 3, 4}
	sealed := cUp.seal(nil, ad, []byte("abcdefgh"), 77)
	plain, err := sUp.open(ad, sealed, 77)
	if err != nil || string(plain) != "abcdefgh" {
		t.Fatal("open", err)
	}
	if cUp.mask(sealed) != sUp.mask(sealed) {
		t.Fatal("mask")
	}
	sealed[3] ^= 1
	if _, err := sUp.open(ad, sealed, 77); err == nil {
		t.Fatal("tamper accepted")
	}
	if _, err := cDown.open(ad, sDown.seal(nil, ad, []byte("x"), 1), 2); err == nil {
		t.Fatal("wrong pn accepted")
	}
	reply[40] ^= 1
	if _, _, _, err := clientFinish(pub, eph, reply); err == nil {
		t.Fatal("forged hello accepted")
	}
}

func TestDNSRoundTrip(t *testing.T) {
	z, _ := parseZone("t.example.com")
	for _, nameLen := range []int{101, 253} {
		n := z.maxPayload(nameLen)
		payload := make([]byte, n)
		rand.Read(payload)
		msg := appendQuery(nil, 7, payload, z, 1232)
		end, _ := skipName(msg, hdrLen)
		if pres := end - hdrLen - 2; pres > nameLen {
			t.Fatalf("name %d chars > %d", pres, nameLen)
		}
		// Resolvers may randomize case.
		up := bytes.ToUpper(msg[hdrLen:end])
		copy(msg[hdrLen:], up)
		q, err := parseQuery(msg, z)
		if err != nil || !bytes.Equal(q.payload, payload) || q.edns != 1232 {
			t.Fatalf("nameLen %d: payload mismatch (%v)", nameLen, err)
		}
		cap := txtCapacity(q, 512)
		data := make([]byte, cap)
		rand.Read(data)
		ans := appendAnswer(nil, q, rcodeOK, data)
		if len(ans) > 512 {
			t.Fatalf("answer %d > 512", len(ans))
		}
		a, err := parseAnswer(ans)
		if err != nil || !bytes.Equal(a.txt, data) || a.txn != 7 {
			t.Fatal("answer mismatch", err)
		}
	}
}

func TestDecodePN(t *testing.T) {
	if decodePN(0xFFFE, true, 0x0001) != 0x10001 {
		t.Fatal("wrap forward")
	}
	if decodePN(0x10005, true, 0xFFF0) != 0xFFF0 {
		t.Fatal("reorder back")
	}
	if decodePN(0, false, 5) != 5 {
		t.Fatal("first")
	}
}
