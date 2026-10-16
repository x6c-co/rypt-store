package provider

import (
	"context"
	"errors"
	"net/http"

	"github.com/x6c-co/rypt"
)

// Rypt wraps keys under a rypt.dev key through the github.com/x6c-co/rypt
// module's envelope operations (core 5.3):
//
//	Wrap   -> rypt.Client.Wrap(ctx, keyID, key, aad)
//	Unwrap -> rypt.Client.Unwrap(ctx, wrap.KeyRef, wrapped, aad)
//	Rewrap -> Unwrap, then Wrap under the configured key
//
// The module accepts AAD on wrap and unwrap, so the binding of core 5.5
// holds. Known gaps in module v0.1.0, recorded in docs/GAPS.md:
//
//   - rypt.Client.Rewrap is documented for Encrypt ciphertexts only, not for
//     wrapped data keys, so Rewrap here costs two metered operations and the
//     key passes through this process briefly.
//   - Successful responses carry no key version, so KeyVersion stays empty.
//   - Successful responses expose no request ID; only errors carry one.
//
// The module already retries transient failures (three attempts), so this
// adapter adds no retry loop of its own.
type Rypt struct {
	c     *rypt.Client
	keyID string
}

// RyptOptions configures NewRypt.
type RyptOptions struct {
	Token     string
	KeyID     string
	BaseURL   string // empty for rypt.DefaultBaseURL
	UserAgent string
	// HTTPClient overrides the transport, for tests.
	HTTPClient *http.Client
}

func NewRypt(o RyptOptions) (*Rypt, error) {
	if o.KeyID == "" {
		return nil, errors.New("rypt key ID is empty")
	}
	opts := []rypt.Option{rypt.WithUserAgent(o.UserAgent)}
	if o.BaseURL != "" {
		opts = append(opts, rypt.WithBaseURL(o.BaseURL))
	}
	if o.HTTPClient != nil {
		opts = append(opts, rypt.WithHTTPClient(o.HTTPClient))
	}
	c, err := rypt.NewClient(o.Token, opts...)
	if err != nil {
		return nil, err
	}
	return &Rypt{c: c, keyID: o.KeyID}, nil
}

func (r *Rypt) Name() string   { return "rypt" }
func (r *Rypt) KeyRef() string { return r.keyID }
func (r *Rypt) RewrapOps() int { return 2 }

func (r *Rypt) Wrap(ctx context.Context, key, aad []byte) (WrappedKey, error) {
	wrapped, err := r.c.Wrap(ctx, r.keyID, key, aad)
	if err != nil {
		return WrappedKey{}, classifyRypt(ctx, "wrap", err)
	}
	return WrappedKey{Provider: "rypt", KeyRef: r.keyID, Ciphertext: wrapped}, nil
}

func (r *Rypt) Unwrap(ctx context.Context, w WrappedKey, aad []byte) ([]byte, error) {
	if w.Provider != "rypt" {
		return nil, &Error{Provider: "rypt", Op: "unwrap", Kind: Fatal, Err: errors.New("wrap belongs to provider " + w.Provider)}
	}
	// A wrap is unwrapped under the key that made it, which may differ from
	// the key new wraps use.
	k, err := r.c.Unwrap(ctx, w.KeyRef, w.Ciphertext, aad)
	if err != nil {
		return nil, classifyRypt(ctx, "unwrap", err)
	}
	return k, nil
}

func (r *Rypt) Rewrap(ctx context.Context, w WrappedKey, aad []byte) (WrappedKey, error) {
	k, err := r.Unwrap(ctx, w, aad)
	if err != nil {
		return WrappedKey{}, err
	}
	defer clear(k)
	return r.Wrap(ctx, k, aad)
}

// classifyRypt maps a module error onto the outage policy (core 5.6):
//
//	transport failure, malformed response, HTTP >= 500 -> Outage
//	HTTP 429 (ops_cap_reached, rate_limited)           -> Quota
//	any other API error, and argument errors           -> Fatal
func classifyRypt(ctx context.Context, op string, err error) error {
	pe := &Error{Provider: "rypt", Op: op, Kind: Fatal, Err: err}
	var re *rypt.Error
	switch {
	case errors.As(err, &re):
		pe.RequestID = re.RequestID
		pe.Code = string(re.Code)
		switch {
		case re.Kind == rypt.KindTransport, re.Kind == rypt.KindResponse:
			pe.Kind = Outage
		case re.StatusCode == http.StatusTooManyRequests, re.Code == rypt.CodeOpsCapReached, re.Code == rypt.CodeRateLimited:
			pe.Kind = Quota
			pe.Cap, pe.ResetsAt = re.Cap, re.ResetsAt
		case re.StatusCode >= 500:
			pe.Kind = Outage
		}
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
		// The client's own timeout, not the caller's deadline.
		pe.Kind = Outage
	}
	return pe
}
