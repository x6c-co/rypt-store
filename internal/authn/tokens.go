package authn

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/x6c-co/rypt-store/internal/ids"
)

// Token prefixes.
const (
	ServiceTokenPrefix = "rst_" // feature 01 2.4
	CLISessionPrefix   = "rsc_" // core 7.4
)

// SessionCookie is the web session cookie (core 7.3).
const SessionCookie = "__Host-rypt_store_session"

// EqualConstantTime compares two strings in constant time.
func EqualConstantTime(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NewWebSessionToken returns an opaque 256-bit token.
func NewWebSessionToken() string {
	return base64.RawURLEncoding.EncodeToString(ids.RandomBytes(32))
}

// NewCLISessionToken returns an rsc_ token.
func NewCLISessionToken() string {
	return CLISessionPrefix + ids.RandomToken(32)
}

// ServiceToken is a parsed rst_<id>_<secret> token.
type ServiceToken struct {
	ID     string // UUID
	Secret string // Crockford base32 of 32 random bytes
}

// NewServiceToken returns a token for a new token ID and its full string.
func NewServiceToken(id string) (ServiceToken, string, error) {
	enc, err := ids.UUIDToCrockford(id)
	if err != nil {
		return ServiceToken{}, "", err
	}
	t := ServiceToken{ID: id, Secret: ids.RandomToken(32)}
	return t, ServiceTokenPrefix + enc + "_" + t.Secret, nil
}

var errMalformedToken = errors.New("malformed service token")

// ParseServiceToken splits an rst_ token.
func ParseServiceToken(s string) (ServiceToken, error) {
	rest, ok := strings.CutPrefix(s, ServiceTokenPrefix)
	if !ok {
		return ServiceToken{}, errMalformedToken
	}
	idPart, secret, ok := strings.Cut(rest, "_")
	if !ok || len(idPart) != 26 || len(secret) < 32 {
		return ServiceToken{}, errMalformedToken
	}
	id, err := ids.CrockfordToUUID(idPart)
	if err != nil {
		return ServiceToken{}, errMalformedToken
	}
	return ServiceToken{ID: id, Secret: secret}, nil
}

// SecretHash is what service_tokens.token_hash stores: SHA-256 of the
// secret part.
func (t ServiceToken) SecretHash() string { return ids.HashToken(t.Secret) }

// Prefix is the first 8 characters of the secret part, for display.
func (t ServiceToken) Prefix() string { return t.Secret[:8] }
