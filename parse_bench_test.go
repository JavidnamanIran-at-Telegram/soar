package soar

import (
	"crypto/rand"
	"testing"
)

// benchQuery is a data query of the size a path settles on at the safe name length.
func benchQuery(tb testing.TB, z zone) []byte {
	tb.Helper()
	payload := make([]byte, z.maxPayload(101))
	rand.Read(payload)
	return appendQuery(nil, 0x1234, payload, z, typeTXT, 1232)
}

// BenchmarkParseQuery is the server's hottest path: every query, hello or data, goes through it.
func BenchmarkParseQuery(b *testing.B) {
	z, err := parseZone(testZone)
	if err != nil {
		b.Fatal(err)
	}
	msg := benchQuery(b, z)
	b.ReportAllocs()
	for b.Loop() {
		q, err := parseQuery(msg, z)
		if err != nil || q.payload == nil {
			b.Fatal("parse failed")
		}
	}
}

// BenchmarkParseQueryLabel is the same with an account label to pick out of the name.
func BenchmarkParseQueryLabel(b *testing.B) {
	z, err := parseZone(testZone)
	if err != nil {
		b.Fatal(err)
	}
	z.userLabel = true
	inner, err := parseZone("0123456789abcdef." + testZone)
	if err != nil {
		b.Fatal(err)
	}
	msg := benchQuery(b, inner)
	b.ReportAllocs()
	for b.Loop() {
		q, err := parseQuery(msg, z)
		if err != nil || q.payload == nil || q.label != "0123456789abcdef" {
			b.Fatal("parse failed")
		}
	}
}
