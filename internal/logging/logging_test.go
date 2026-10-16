package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelDebug)
	log.With("rypt_token", "ry_live_abc").Info("hello",
		"value", "hunter2",
		"password", "pw-123",
		"secret_name", "DATABASE_URL",
		slog.Group("req", "authorization", "Bearer xyz", "path", "/api"),
		"session_token", "s3ss",
		"dek", []byte{1, 2},
	)
	out := buf.String()
	for _, leaked := range []string{"ry_live_abc", "hunter2", "pw-123", "Bearer xyz", "s3ss"} {
		if strings.Contains(out, leaked) {
			t.Errorf("log leaked %q: %s", leaked, out)
		}
	}
	for _, kept := range []string{"DATABASE_URL", "/api", "hello"} {
		if !strings.Contains(out, kept) {
			t.Errorf("log dropped %q: %s", kept, out)
		}
	}
}

func TestIsSensitiveKey(t *testing.T) {
	for _, k := range []string{"token", "rypt_token", "Password", "req.cookie", "secret"} {
		if !IsSensitiveKey(k) {
			t.Errorf("%q should be sensitive", k)
		}
	}
	for _, k := range []string{"secret_name", "token_prefix", "path", "user_id"} {
		if IsSensitiveKey(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
}
