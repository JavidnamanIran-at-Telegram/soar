package soar

import (
	"context"
	"net/http"
	"time"
)

// NewRoundTripper waits for a tunnel session (bounded by ctx) and returns an HTTP transport whose
// connections ride the tunnel. TLS runs end to end through it, so the server only relays
// ciphertext. addr is unused: each request dials its own host. With Close, MaxLength and
// RequestTimeout, this satisfies kindling's DNS-tunnel transport (dnstt.DNSTT).
func (c *Client) NewRoundTripper(ctx context.Context, _ string) (http.RoundTripper, error) {
	if _, err := c.session(ctx); err != nil {
		return nil, err
	}
	return &http.Transport{
		DialContext:         c.DialContext,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
		// Idle keep-alives hold a stream open, and an open stream keeps a poll outstanding.
		IdleConnTimeout:     5 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
	}, nil
}

// MaxLength caps request bodies: uploads ride ~50-byte queries, so big ones belong elsewhere.
func (c *Client) MaxLength() int { return 64 << 10 }

// RequestTimeout bounds a request through the tunnel, including session setup.
func (c *Client) RequestTimeout() time.Duration { return 90 * time.Second }
