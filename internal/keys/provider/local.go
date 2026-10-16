package provider

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Local wraps keys with AES-256-GCM under a key-encryption key (KEK) held
// by the server (core 5.3).
type Local struct {
	aead cipher.AEAD
	ref  string
}

// NewLocal returns a local provider for a 32-byte KEK. The provider keeps
// only the expanded cipher, so the caller may clear kek afterwards.
func NewLocal(kek []byte) (*Local, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("local KEK must be 32 bytes, got %d", len(kek))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Local{aead: aead, ref: Fingerprint(kek)}, nil
}

// Fingerprint is the first 16 hex characters of the KEK's SHA-256.
func Fingerprint(kek []byte) string {
	s := sha256.Sum256(kek)
	return hex.EncodeToString(s[:])[:16]
}

func (l *Local) Name() string   { return "local" }
func (l *Local) KeyRef() string { return l.ref }
func (l *Local) RewrapOps() int { return 0 }

func (l *Local) Wrap(_ context.Context, key, aad []byte) (WrappedKey, error) {
	nonce := make([]byte, l.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return WrappedKey{}, err
	}
	ct := l.aead.Seal(nonce, nonce, key, aad)
	return WrappedKey{Provider: "local", KeyRef: l.ref, Ciphertext: ct}, nil
}

func (l *Local) Unwrap(_ context.Context, w WrappedKey, aad []byte) ([]byte, error) {
	if w.Provider != "local" {
		return nil, &Error{Provider: "local", Op: "unwrap", Kind: Fatal, Err: fmt.Errorf("wrap belongs to provider %q", w.Provider)}
	}
	if w.KeyRef != l.ref {
		return nil, &Error{Provider: "local", Op: "unwrap", Kind: Fatal,
			Err: fmt.Errorf("wrap was made under KEK %s but the loaded KEK is %s", w.KeyRef, l.ref)}
	}
	ns := l.aead.NonceSize()
	if len(w.Ciphertext) < ns+l.aead.Overhead() {
		return nil, &Error{Provider: "local", Op: "unwrap", Kind: Fatal, Err: errors.New("wrapped key is truncated")}
	}
	pt, err := l.aead.Open(nil, w.Ciphertext[:ns], w.Ciphertext[ns:], aad)
	if err != nil {
		return nil, &Error{Provider: "local", Op: "unwrap", Kind: Fatal, Err: errors.New("wrapped key failed authentication")}
	}
	return pt, nil
}

// Rewrap re-wraps under a fresh nonce; the local KEK has no versions.
func (l *Local) Rewrap(ctx context.Context, w WrappedKey, aad []byte) (WrappedKey, error) {
	k, err := l.Unwrap(ctx, w, aad)
	if err != nil {
		return WrappedKey{}, err
	}
	defer clear(k)
	return l.Wrap(ctx, k, aad)
}

// LoadOrCreateKEK returns the local KEK from the base64 environment value
// when set, else from path, generating the file (mode 0600) when it does not
// exist. created reports whether a new KEK file was written.
func LoadOrCreateKEK(path, envB64 string) (kek []byte, created bool, err error) {
	if envB64 != "" {
		b, err := base64.StdEncoding.DecodeString(envB64)
		if err != nil || len(b) != 32 {
			return nil, false, errors.New("RYPT_STORE_LOCAL_KEK must be 32 bytes of standard base64")
		}
		return b, false, nil
	}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(b) != 32 {
			return nil, false, fmt.Errorf("KEK file %s holds %d bytes, want 32", path, len(b))
		}
		if fi, statErr := os.Stat(path); statErr == nil && fi.Mode().Perm()&0o077 != 0 {
			return nil, false, fmt.Errorf("KEK file %s is readable by group or others (mode %o); chmod 600 it", path, fi.Mode().Perm())
		}
		return b, false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, false, fmt.Errorf("read KEK file: %w", err)
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("create KEK directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("create KEK file: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return nil, false, err
	}
	if err := f.Close(); err != nil {
		return nil, false, err
	}
	return b, true, nil
}
