package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/getlantern/soar"
)

// accounts is the server's account table, read from a JSON file and re-read when it changes, so
// a panel can add and remove accounts without restarting the server and dropping every session.
//
// The file is a list of accounts:
//
//	[
//	  {"label": "0123456789abcdef"},
//	  {"label": "member02", "key_id": "a1b2c3d4e5f60708", "key": "<base64, >=16 bytes>"}
//	]
//
// A label is what the client puts in the query name (-identify-by-label). A key id and key are
// what a client proves instead, inside the handshake (Config.Identity), which is what a client
// should use when it can be changed: a label in the name is visible to every resolver on the
// path. An account may have either or both.
type accounts struct {
	path string
	log  *slog.Logger

	mu     sync.RWMutex
	byName map[string]*Account
	byKey  map[[soar.IdentKeyLen]byte]*Account
	at     time.Time
	size   int64
}

// Account is one entry of the file. Name is what metering and logs call it.
type Account struct {
	Label string `json:"label"`
	KeyID string `json:"key_id"`
	Key   string `json:"key"`

	key []byte
}

// Name is how an account is reported. It is the label when there is one, else the key id - and
// a key id is the better thing to log, since it is never on the wire in clear.
func (a *Account) Name() string {
	if a.KeyID != "" {
		return a.KeyID
	}
	return a.Label
}

func loadAccounts(path string, log *slog.Logger) (*accounts, error) {
	a := &accounts{path: path, log: log}
	if err := a.reload(); err != nil {
		return nil, err
	}
	return a, nil
}

// reload replaces the table from the file. A file that cannot be read or does not parse leaves
// the table as it was: a half-written file must not log every account out.
func (a *accounts) reload() error {
	st, err := os.Stat(a.path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(a.path)
	if err != nil {
		return err
	}
	var list []*Account
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("%s: %w", a.path, err)
	}
	byName := make(map[string]*Account, len(list))
	byKey := make(map[[soar.IdentKeyLen]byte]*Account, len(list))
	for _, acct := range list {
		if acct.Label != "" {
			byName[acct.Label] = acct
		}
		if acct.KeyID == "" {
			continue
		}
		id, err := hex.DecodeString(acct.KeyID)
		if err != nil || len(id) != soar.IdentKeyLen {
			return fmt.Errorf("%s: key_id must be %d hex bytes", a.path, soar.IdentKeyLen)
		}
		if acct.key, err = base64.StdEncoding.DecodeString(acct.Key); err != nil || len(acct.key) < 16 {
			return fmt.Errorf("%s: key must be base64 and at least 16 bytes", a.path)
		}
		var k [soar.IdentKeyLen]byte
		copy(k[:], id)
		byKey[k] = acct
	}
	a.mu.Lock()
	a.byName, a.byKey, a.at, a.size = byName, byKey, st.ModTime(), st.Size()
	a.mu.Unlock()
	a.log.Info("accounts loaded", "labels", len(byName), "keys", len(byKey))
	return nil
}

// refresh re-reads the file when its timestamp or size has moved.
func (a *accounts) refresh() {
	st, err := os.Stat(a.path)
	if err != nil {
		a.log.Warn("accounts file unreadable; keeping the table", "err", err)
		return
	}
	a.mu.RLock()
	same := st.ModTime().Equal(a.at) && st.Size() == a.size
	a.mu.RUnlock()
	if same {
		return
	}
	if err := a.reload(); err != nil {
		a.log.Warn("accounts file rejected; keeping the table", "err", err)
	}
}

// watch re-reads the file every interval until ctx ends.
func (a *accounts) watch(done <-chan struct{}, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			a.refresh()
		}
	}
}

// verifyLabel is ServerConfig.VerifyLabel.
func (a *accounts) verifyLabel(label string) (any, bool) {
	a.mu.RLock()
	acct, ok := a.byName[label]
	a.mu.RUnlock()
	return acct, ok
}

// verifyClient is ServerConfig.VerifyClient. It runs with a session's lock held, so it does the
// least it can: one map read under a read lock.
func (a *accounts) verifyClient(keyID [soar.IdentKeyLen]byte) ([]byte, any, bool) {
	a.mu.RLock()
	acct, ok := a.byKey[keyID]
	a.mu.RUnlock()
	if !ok {
		return nil, nil, false
	}
	return acct.key, acct, true
}
