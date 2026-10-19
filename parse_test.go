package soar

import (
	"errors"
	"testing"
)

func TestOverlongNameIsRefused(t *testing.T) {
	// A DNS name is at most 255 wire bytes. A message may still be framed with far more, so
	// the parser bounds it rather than taking the sender's word for how much work to do.
	msg := []byte{0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for range 20 {
		msg = append(msg, maxLabel)
		msg = append(msg, make([]byte, maxLabel)...)
	}
	msg = append(msg, 0, 0, byte(typeTXT), 0, classIN)
	z, _ := parseZone(testZone)
	if _, err := parseQuery(msg, z); !errors.Is(err, errDNS) {
		t.Fatalf("a %d-byte name parsed: %v", len(msg)-hdrLen, err)
	}
}

func TestUnknownExtensionSubTypeIsSkipped(t *testing.T) {
	// What the reserved type buys: a frame this peer does not understand costs it nothing, and
	// the frames after it still arrive. SPEC §6 makes an unknown *type* fatal, which is why one
	// type with sub-types had to be reserved while v1 is open.
	b := appendVarint([]byte{frExt}, 0x3F) // a sub-type this build knows nothing about
	b = appendVarint(b, 3)
	b = append(b, 1, 2, 3)
	b = append(b, frPing)
	var types []byte
	if err := parseFrames(b, func(f *frame) error {
		types = append(types, f.typ)
		return nil
	}); err != nil {
		t.Fatalf("unknown sub-type: %v", err)
	}
	if len(types) != 2 || types[0] != frExt || types[1] != frPing {
		t.Fatalf("frames %x", types)
	}
}

func TestExtensionFrameLengthIsBounded(t *testing.T) {
	b := appendVarint(appendVarint([]byte{frExt}, 1), maxExtBody+1)
	b = append(b, make([]byte, 8)...)
	if err := parseFrames(b, func(*frame) error { return nil }); !errors.Is(err, errFrame) {
		t.Fatalf("oversized body: %v, want errFrame", err)
	}
	// And a body the packet cannot hold is short, not a read past the end.
	b = appendVarint(appendVarint([]byte{frExt}, 1), 64)
	b = append(b, 1, 2, 3)
	if err := parseFrames(b, func(*frame) error { return nil }); err == nil {
		t.Fatal("a body longer than the packet parsed")
	}
}
