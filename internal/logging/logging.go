// Package logging builds the server's slog logger. Its handler redacts any
// attribute whose key names sensitive material, so that a careless log call
// cannot leak a secret value, key, token, or password (core 15).
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// Redacted replaces every redacted attribute value.
const Redacted = "[redacted]"

// sensitiveKeys are matched against the lower-cased attribute key: an exact
// match or a "_"/"." separated suffix redacts the attribute.
var sensitiveKeys = []string{
	"password", "passwd", "secret", "token", "value", "plaintext", "ciphertext",
	"kek", "dek", "key_material", "material", "authorization", "cookie",
	"totp", "recovery_code", "setup_token", "body",
}

// IsSensitiveKey reports whether an attribute key names sensitive material.
func IsSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if k == s || strings.HasSuffix(k, "_"+s) || strings.HasSuffix(k, "."+s) {
			return true
		}
	}
	return false
}

// New returns a JSON logger writing to w at the given level.
func New(w io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(NewRedactingHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})))
}

// RedactingHandler wraps another handler and redacts sensitive attributes,
// including inside groups and in WithAttrs.
type RedactingHandler struct{ next slog.Handler }

func NewRedactingHandler(next slog.Handler) *RedactingHandler { return &RedactingHandler{next: next} }

func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(redact(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redact(a)
	}
	return &RedactingHandler{next: h.next.WithAttrs(out)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{next: h.next.WithGroup(name)}
}

func redact(a slog.Attr) slog.Attr {
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		g := v.Group()
		out := make([]slog.Attr, len(g))
		for i, ga := range g {
			out[i] = redact(ga)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	}
	return slog.Attr{Key: a.Key, Value: v}
}
