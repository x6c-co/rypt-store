// Package keys owns the key hierarchy (core 5): the instance key, root key,
// project keys and data keys, their wraps, the unwrapped-key cache, the
// outage policy, and re-wrap migrations.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
)

// KeySize is the size of every key in the hierarchy.
const KeySize = 32

// redacted is what key-holding values print as (core 5.6).
const redacted = "[key material redacted]"

// Material holds key bytes. It prints as a redaction marker through fmt,
// %#v, and slog, so key bytes cannot reach logs, errors, or panics by
// accident.
type Material struct{ b []byte }

func (m Material) String() string               { return redacted }
func (m Material) GoString() string             { return redacted }
func (m Material) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }
func (m Material) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (m Material) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Clear overwrites the key bytes.
func (m Material) Clear() { clear(m.b) }

// newKey returns 32 random bytes.
func newKey() []byte {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

// seal encrypts with AES-256-GCM and a random 96-bit nonce (core X3) and
// returns nonce || ciphertext || tag.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// ErrDecrypt means a ciphertext failed authentication: wrong key, wrong
// AAD (for example a ciphertext copied to another row), or tampering.
var ErrDecrypt = errors.New("ciphertext failed authentication")

func open(key, sealed, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(sealed) < ns+aead.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := aead.Open(nil, sealed[:ns], sealed[ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key is %d bytes, want %d", len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
