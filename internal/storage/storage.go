// Package storage persists credentials (tokens + proxy secrets) using Windows
// DPAPI (user-scoped, no transfer between machines). It replaces the Android
// SecurePreferences/TokenStore pair.
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"foxyvpn/internal/model"
	"foxyvpn/internal/settings"
)

func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func dataDir() string { return settings.AppDataDir() }

func protectFile(name string, data []byte) error {
	blob, err := dpapiProtect(data)
	if err != nil {
		return fmt.Errorf("dpapi protect: %w", err)
	}
	path := filepath.Join(dataDir(), name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func unprotectFile(name string) ([]byte, bool, error) {
	path := filepath.Join(dataDir(), name)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if len(raw) == 0 {
		return nil, false, nil
	}
	plain, err := dpapiUnprotect(raw)
	if err != nil {
		return nil, true, fmt.Errorf("dpapi unprotect: %w", err)
	}
	return plain, true, nil
}

// ---- Credentials (proxy secrets etc.) ----

type Credentials struct {
	LocalProxyUsername  string `json:"localProxyUsername,omitempty"`
	LocalProxyPassword  string `json:"localProxyPassword,omitempty"`
	UpstreamProxyType   string `json:"upstreamProxyType,omitempty"`
	UpstreamProxyHost   string `json:"upstreamProxyHost,omitempty"`
	UpstreamProxyPort   int    `json:"upstreamProxyPort,omitempty"`
	UpstreamProxyUsername string `json:"upstreamProxyUsername,omitempty"`
	UpstreamProxyPassword string `json:"upstreamProxyPassword,omitempty"`
}

type CredentialsStore struct {
	mu   sync.Mutex
	data Credentials
}

func LoadCredentials() (*CredentialsStore, error) {
	c := &CredentialsStore{}
	plain, existed, err := unprotectFile("credentials.bin")
	if err != nil {
		return nil, err
	}
	if existed && len(plain) > 0 {
		_ = json.Unmarshal(plain, &c.data)
	}
	return c, nil
}

func (c *CredentialsStore) Get() Credentials {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data
}

func (c *CredentialsStore) Save(mutate func(*Credentials)) error {
	c.mu.Lock()
	mutate(&c.data)
	raw, _ := json.Marshal(c.data)
	c.mu.Unlock()
	return protectFile("credentials.bin", raw)
}

// ---- TokenStore (port of TokenStore.kt) ----

type tokenFile struct {
	Auth     *model.RuntimeAuth `json:"auth,omitempty"`
	Epoch    int64              `json:"epoch"`
}

type TokenStore struct {
	mu      sync.Mutex
	epoch   int64
	auth    *model.RuntimeAuth
	storageErr string
}

func NewTokenStore() *TokenStore {
	t := &TokenStore{}
	plain, existed, err := unprotectFile("tokens.bin")
	if err != nil {
		// Key unavailable on this machine (e.g. file copied from elsewhere):
		// surface a storage error, mirroring SecureStorageException semantics.
		t.storageErr = err.Error()
		return t
	}
	if existed && len(plain) > 0 {
		var tf tokenFile
		if json.Unmarshal(plain, &tf) == nil {
			t.epoch = tf.Epoch
			t.auth = tf.Auth
		}
	}
	return t
}

func (t *TokenStore) SessionEpoch() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.epoch
}

func (t *TokenStore) StorageError() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.storageErr
}

func (t *TokenStore) LoadAuth() (*model.RuntimeAuth, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.storageErr != "" {
		return nil, &StorageError{Msg: t.storageErr}
	}
	return t.auth, nil
}

type StorageError struct{ Msg string }

func (e *StorageError) Error() string { return e.Msg }

func (t *TokenStore) HasValidAccessToken() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.auth != nil && t.auth.ExpiresAtEpochSeconds > nowUnix()+60
}

func nowUnix() int64 { return time.Now().Unix() }

func (t *TokenStore) SaveAuth(auth model.RuntimeAuth) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	tf := tokenFile{Auth: &auth, Epoch: t.epoch}
	raw, _ := json.Marshal(tf)
	if err := protectFile("tokens.bin", raw); err != nil {
		return err
	}
	t.auth = &auth
	return nil
}

// SaveAuthIfCurrent stores auth only when the session epoch still matches.
func (t *TokenStore) SaveAuthIfCurrent(auth model.RuntimeAuth, epoch int64) error {
	t.mu.Lock()
	if t.epoch != epoch {
		t.mu.Unlock()
		return fmt.Errorf("sign-in was superseded")
	}
	tf := tokenFile{Auth: &auth, Epoch: t.epoch}
	raw, _ := json.Marshal(tf)
	t.mu.Unlock()
	if err := protectFile("tokens.bin", raw); err != nil {
		return err
	}
	t.mu.Lock()
	if t.epoch == epoch {
		t.auth = &auth
	}
	t.mu.Unlock()
	return nil
}

// CompleteLoginIfCurrent atomically moves to a new epoch and stores auth.
func (t *TokenStore) CompleteLoginIfCurrent(auth model.RuntimeAuth, epoch int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.epoch != epoch {
		return fmt.Errorf("sign-in was superseded")
	}
	t.epoch++
	tf := tokenFile{Auth: &auth, Epoch: t.epoch}
	raw, _ := json.Marshal(tf)
	if err := protectFile("tokens.bin", raw); err != nil {
		return err
	}
	t.auth = &auth
	return nil
}

func (t *TokenStore) ClearIfCurrent(epoch int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.epoch != epoch {
		return false
	}
	t.epoch++
	_ = os.Remove(filepath.Join(dataDir(), "tokens.bin"))
	t.auth = nil
	return true
}

// Clear force-clears regardless of epoch (sign-out).
func (t *TokenStore) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.epoch++
	_ = os.Remove(filepath.Join(dataDir(), "tokens.bin"))
	t.auth = nil
}

func (t *TokenStore) InvalidateEpoch() (newEpoch int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.epoch++
	return t.epoch
}


