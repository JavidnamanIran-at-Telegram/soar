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
