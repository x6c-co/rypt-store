package provider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

var ctx = context.Background()

func TestLocalWrapUnwrap(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, 32)
	l, err := NewLocal(kek)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	w, err := l.Wrap(ctx, key, []byte("aad-1"))
	if err != nil {
		t.Fatal(err)
	}
	if w.KeyRef != Fingerprint(kek) || len(w.KeyRef) != 16 {
		t.Fatalf("keyref = %s", w.KeyRef)
	}
	got, err := l.Unwrap(ctx, w, []byte("aad-1"))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrap = %x %v", got, err)
	}
	if _, err := l.Unwrap(ctx, w, []byte("aad-2")); err == nil {
		t.Fatal("unwrap with other AAD succeeded")
	}
	// A different KEK is detected by KeyRef before decryption.
	other, _ := NewLocal(bytes.Repeat([]byte{8}, 32))
	_, err = other.Unwrap(ctx, w, []byte("aad-1"))
	if err == nil || !strings.Contains(err.Error(), "loaded KEK") || KindOf(err) != Fatal {
		t.Fatalf("wrong KEK: %v", err)
	}
	rw, err := l.Rewrap(ctx, w, []byte("aad-1"))
	if err != nil || bytes.Equal(rw.Ciphertext, w.Ciphertext) {
		t.Fatalf("rewrap = %v", err)
	}
}

func TestLoadOrCreateKEK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "local.kek")
	k1, created, err := LoadOrCreateKEK(path, "")
	if err != nil || !created || len(k1) != 32 {
		t.Fatalf("create: %v %v", created, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
	k2, created, err := LoadOrCreateKEK(path, "")
	if err != nil || created || !bytes.Equal(k1, k2) {
		t.Fatalf("reload: %v %v", created, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKEK(path, ""); err == nil {
		t.Fatal("world-readable KEK accepted")
	}
	env := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	k3, _, err := LoadOrCreateKEK(filepath.Join(dir, "unused"), env)
	if err != nil || k3[0] != 1 {
		t.Fatalf("env KEK: %v", err)
	}
}

// fakeRyptAPI serves /v1/keys/{id}/wrap and /unwrap like rypt.dev, with an
// injectable status.
type fakeRyptAPI struct {
	status atomic.Int32
	code   atomic.Value
	calls  atomic.Int32
}

func (f *fakeRyptAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if st := int(f.status.Load()); st != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_123")
		w.WriteHeader(st)
		code, _ := f.code.Load().(string)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": code, "message": "injected", "request_id": "req_123"})
		return
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/wrap"):
		// "Wrap" by prefixing the AAD so unwrap can check it.
		dek, _ := base64.StdEncoding.DecodeString(body["dek"])
		aad, _ := base64.StdEncoding.DecodeString(body["aad"])
		wrapped := append(append([]byte{byte(len(aad))}, aad...), dek...)
		_ = json.NewEncoder(w).Encode(map[string]string{"wrapped": base64.StdEncoding.EncodeToString(wrapped)})
	case strings.HasSuffix(r.URL.Path, "/unwrap"):
		wrapped, _ := base64.StdEncoding.DecodeString(body["wrapped"])
		aad, _ := base64.StdEncoding.DecodeString(body["aad"])
		n := int(wrapped[0])
		if !bytes.Equal(wrapped[1:1+n], aad) {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_ciphertext", "message": "aad mismatch"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"dek": base64.StdEncoding.EncodeToString(wrapped[1+n:])})
	default:
		w.WriteHeader(404)
	}
}

func newRyptForTest(t *testing.T) (*Rypt, *fakeRyptAPI) {
	t.Helper()
	api := &fakeRyptAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	r, err := NewRypt(RyptOptions{Token: "ry_test_token", KeyID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
		BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), UserAgent: "rypt-store/test"})
	if err != nil {
		t.Fatal(err)
	}
	return r, api
}

func TestRyptAdapterRoundTrip(t *testing.T) {
	r, api := newRyptForTest(t)
	key := bytes.Repeat([]byte{5}, 32)
	w, err := r.Wrap(ctx, key, []byte("ctx-a"))
	if err != nil {
		t.Fatal(err)
	}
	if w.Provider != "rypt" || w.KeyRef != r.KeyRef() || w.KeyVersion != "" {
		t.Fatalf("wrapped = %+v", w)
	}
	got, err := r.Unwrap(ctx, w, []byte("ctx-a"))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrap = %v", err)
	}
	// AAD is passed through: a different AAD is refused by the API.
	if _, err := r.Unwrap(ctx, w, []byte("ctx-b")); KindOf(err) != Fatal {
		t.Fatalf("aad mismatch kind = %v (%v)", KindOf(err), err)
	}
	api.calls.Store(0)
	if _, err := r.Rewrap(ctx, w, []byte("ctx-a")); err != nil {
		t.Fatal(err)
	}
	if n := api.calls.Load(); int(n) != r.RewrapOps() {
		t.Fatalf("rewrap made %d calls, RewrapOps says %d", n, r.RewrapOps())
	}
}

func TestRyptErrorClassification(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   Kind
	}{
		{500, "internal_error", Outage},
		{503, "unavailable", Outage},
		{429, "ops_cap_reached", Quota},
		{429, "rate_limited", Quota},
		{401, "unauthorized", Fatal},
		{402, "billing_required", Fatal},
		{404, "not_found", Fatal},
		{409, "key_pending_deletion", Fatal},
	}
	for _, c := range cases {
		r, api := newRyptForTest(t)
		api.status.Store(int32(c.status))
		api.code.Store(c.code)
		_, err := r.Wrap(ctx, bytes.Repeat([]byte{1}, 32), nil)
		var pe *Error
		if !errors.As(err, &pe) {
			t.Fatalf("%d %s: not a provider error: %v", c.status, c.code, err)
		}
		if pe.Kind != c.want {
			t.Errorf("%d %s: kind = %v, want %v", c.status, c.code, pe.Kind, c.want)
		}
		if pe.RequestID != "req_123" {
			t.Errorf("%d %s: request id = %q", c.status, c.code, pe.RequestID)
		}
	}
	// A transport failure is an outage.
	r, err := NewRypt(RyptOptions{Token: "ry_x", KeyID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", BaseURL: "http://localhost:1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Wrap(ctx, bytes.Repeat([]byte{1}, 32), nil)
	if KindOf(err) != Outage {
		t.Fatalf("transport kind = %v (%v)", KindOf(err), err)
	}
}
