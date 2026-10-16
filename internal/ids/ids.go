// Package ids generates identifiers and timestamps in the formats the
// storage layer uses (core 4.3): UUIDv7 strings and fixed-width RFC 3339 UTC
// timestamps that sort lexically in both SQLite and PostgreSQL.
package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TimeFormat is RFC 3339 in UTC with exactly three fractional digits, so
// that string order matches time order.
const TimeFormat = "2006-01-02T15:04:05.000Z"

// New returns a new UUIDv7 string.
func New() string {
	return uuid.Must(uuid.NewV7()).String()
}

// Valid reports whether s is a UUID string.
func Valid(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil && len(s) == 36
}

// FormatTime formats t in TimeFormat.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

// ParseTime parses a TimeFormat (or any RFC 3339) string.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// Crockford is base32 with Crockford's alphabet, lower case, no padding.
var Crockford = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// UUIDToCrockford encodes a UUID string's 16 bytes in Crockford base32.
func UUIDToCrockford(id string) (string, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return "", err
	}
	return Crockford.EncodeToString(u[:]), nil
}

// CrockfordToUUID decodes a Crockford base32 string back to a UUID string.
func CrockfordToUUID(s string) (string, error) {
	b, err := Crockford.DecodeString(strings.ToLower(s))
	if err != nil {
		return "", err
	}
	u, err := uuid.FromBytes(b)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// RandomBytes returns n bytes from crypto/rand.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

// RandomToken returns n random bytes encoded in Crockford base32.
func RandomToken(n int) string { return Crockford.EncodeToString(RandomBytes(n)) }

// HashToken returns the hex SHA-256 of a token. The database stores token
// hashes, never tokens (core 7.3).
func HashToken(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

// EqualHash compares two hashes or tokens in constant time (core 15).
func EqualHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
