// Package authn authenticates requests (core 7): local accounts with
// passwords, TOTP and WebAuthn, web and CLI sessions, and service tokens.
// Authenticators sit behind one interface so that OIDC and machine
// identities can be added later without changing handlers.
package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (core 7.2): m=64MiB, t=3, p=2, 16-byte salt.
type Argon2Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	KeyLen    uint32
}

var (
	// PasswordParams hash passwords.
	PasswordParams = Argon2Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32}
	// RecoveryCodeParams hash recovery codes. The codes carry 60 bits of
	// randomness, so lighter parameters keep verifying ten of them cheap.
	RecoveryCodeParams = Argon2Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1, KeyLen: 32}
)

// Password length limits (core 7.2), counted in characters.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 1024
)

// ValidatePassword enforces the length rules; there are no composition rules.
func ValidatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if n > MaxPasswordLen {
		return fmt.Errorf("password must be at most %d characters", MaxPasswordLen)
	}
	return nil
}

// hashSlots bounds concurrent Argon2id computations, which each take
// 64 MiB, so that a burst of logins cannot exhaust memory.
var hashSlots = make(chan struct{}, 4)

// HashPassword returns a PHC string: $argon2id$v=19$m=65536,t=3,p=2$salt$hash.
func HashPassword(pw string) (string, error) { return hash(pw, PasswordParams) }

// HashRecoveryCode hashes a recovery code.
func HashRecoveryCode(code string) (string, error) {
	return hash(NormalizeRecoveryCode(code), RecoveryCodeParams)
}

func hash(secret string, p Argon2Params) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hashSlots <- struct{}{}
	key := argon2.IDKey([]byte(secret), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	<-hashSlots
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("malformed password hash")

// VerifyHash checks secret against a PHC string in constant time.
func VerifyHash(secret, phc string) (bool, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errBadHash
	}
	hashSlots <- struct{}{}
	got := argon2.IDKey([]byte(secret), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	<-hashSlots
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified against when a login names an unknown user, so
// that the response time does not reveal whether the account exists.
var dummyHash, _ = HashPassword("rypt-store-dummy-password")

// VerifyPassword checks a password; with an empty hash it burns the same
// time and fails.
func VerifyPassword(pw, phc string) bool {
	if phc == "" {
		_, _ = VerifyHash(pw, dummyHash)
		return false
	}
	ok, err := VerifyHash(pw, phc)
	return err == nil && ok
}

// recoveryAlphabet avoids look-alike characters.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewRecoveryCodes returns n codes formatted xxxxx-xxxxx-xxxxx (core 7.2).
func NewRecoveryCodes(n int) []string {
	out := make([]string, n)
	for i := range out {
		var b strings.Builder
		buf := make([]byte, 15)
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		for j, c := range buf {
			if j > 0 && j%5 == 0 {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryAlphabet[int(c)%len(recoveryAlphabet)])
		}
		out[i] = b.String()
	}
	return out
}

// NormalizeRecoveryCode lower-cases and drops separators and spaces.
func NormalizeRecoveryCode(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ':
			return -1
		case r >= 'A' && r <= 'Z':
			return r + 32
		}
		return r
	}, code)
}
