// Package provider defines the key providers that wrap the top of the key
// hierarchy (core 5.3): local, with a key-encryption key on disk, and rypt,
// which calls rypt.dev.
package provider

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Provider wraps and unwraps keys under a provider-held key.
type Provider interface {
	Name() string // "local" or "rypt"
	// KeyRef names the key that new wraps are made under.
	KeyRef() string
	Wrap(ctx context.Context, plaintextKey []byte, aad []byte) (WrappedKey, error)
	Unwrap(ctx context.Context, w WrappedKey, aad []byte) ([]byte, error)
	// Rewrap moves a wrap to the provider's current key version.
	Rewrap(ctx context.Context, w WrappedKey, aad []byte) (WrappedKey, error)
	// RewrapOps is how many metered provider operations one Rewrap costs.
	RewrapOps() int
}

// WrappedKey is a key wrapped by a provider.
type WrappedKey struct {
	Provider   string // "local" | "rypt"
	KeyRef     string // local: KEK fingerprint; rypt: rypt key ID (UUID)
	KeyVersion string // rypt key version when returned by the API; empty for local
	Ciphertext []byte
}

// Kind classifies a provider failure for the outage policy (core 5.6).
type Kind int

const (
	// Fatal failures are never outages: bad token, unknown key, wrong KEK,
	// tampered ciphertext.
	Fatal Kind = iota
	// Outage is a network failure or a 5xx; the outage policy applies.
	Outage
	// Quota is a 429 from rypt.dev: a monthly cap or the rate limit.
	Quota
)

func (k Kind) String() string {
	switch k {
	case Outage:
		return "outage"
	case Quota:
		return "quota"
	}
	return "error"
}

// Error is a classified provider failure.
type Error struct {
	Provider string
	Op       string
	Kind     Kind
	// RequestID is the provider's request ID, when it sent one.
	RequestID string
	// Code is the provider's error code, when it sent one.
	Code string
	// Cap and ResetsAt describe a monthly operation cap (Quota only).
	Cap      int64
	ResetsAt time.Time
	Err      error
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s provider %s (%s): %v", e.Provider, e.Op, e.Kind, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// KindOf returns the Kind of a provider error, Fatal for any other error.
func KindOf(err error) Kind {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Kind
	}
	return Fatal
}

// RequestIDOf returns the provider request ID carried by err, if any.
func RequestIDOf(err error) string {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.RequestID
	}
	return ""
}

// Ref formats the wrapper_ref of a provider wrap: "<provider>:<KeyRef>".
func Ref(w WrappedKey) string { return w.Provider + ":" + w.KeyRef }
