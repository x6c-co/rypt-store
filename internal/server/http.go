package server

import (
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/x6c-co/rypt-store/internal/api"
	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authn"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/metrics"
	"github.com/x6c-co/rypt-store/internal/store"
)

// HandlerOptions configures the HTTP handler.
type HandlerOptions struct {
	API           *api.Handlers
	Store         store.Store
	Audit         *audit.Writer
	Authenticator authn.Authenticator
	SPA           fs.FS
	Metrics       *metrics.Metrics
	Logger        *slog.Logger
	// HSTS adds Strict-Transport-Security (core 11: acme and files modes).
	HSTS bool
}

// NewHandler builds the HTTPS handler: API, SPA, and health endpoints.
func NewHandler(o HandlerOptions) http.Handler {
	mux := http.NewServeMux()
	strict := gen.NewStrictHandlerWithOptions(o.API, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteProblem(w, r, badRequest(err), o.Logger)
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteProblem(w, r, err, o.Logger)
		},
	})
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteProblem(w, r, badRequest(err), o.Logger)
		},
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		api.WriteProblem(w, r, &api.Problem{Status: http.StatusNotFound, Code: "not_found", Title: "Not Found", Detail: "no such endpoint"}, o.Logger)
	})
	mux.Handle("/", spaHandler(o.SPA))

	var h http.Handler = mux
	h = gates(o, h)
	h = authenticate(o, h)
	h = withMeta(h)
	h = observe(o, h)
	h = securityHeaders(o.HSTS, h)
	h = requestID(h)
	h = recoverPanics(o.Logger, h)
	return h
}

func badRequest(err error) error {
	return &api.Problem{Status: http.StatusBadRequest, Code: "validation_failed", Title: "Bad Request", Detail: err.Error()}
}

// ---- middleware ----

func recoverPanics(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Error("panic", "request_id", w.Header().Get("X-Request-Id"), "path", r.URL.Path)
				api.WriteProblem(w, r, errors.New("panic"), nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// requestID echoes a well-formed X-Request-Id or generates one (core 9).
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !requestIDPattern.MatchString(id) {
			id = ids.New()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets the headers of core 15 on every response.
func securityHeaders(hsts bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// API responses are per-principal and may carry secret values.
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// observe logs one line per request, never bodies (core 15), and counts it.
func observe(o HandlerOptions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		if o.Metrics != nil {
			o.Metrics.HTTPRequests.WithLabelValues(r.Method, strconv.Itoa(sw.status/100)+"xx").Inc()
		}
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		o.Logger.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(), "request_id", w.Header().Get("X-Request-Id"))
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// withMeta puts request metadata, audit request context, and the response
// writer into the context for the strict handlers.
func withMeta(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := api.RequestMeta{IP: clientIP(r), UserAgent: r.UserAgent(), Origin: r.Header.Get("Origin"), Host: r.Host, TLS: r.TLS != nil}
		if c, err := r.Cookie(authn.SessionCookie); err == nil {
			m.SessionToken = c.Value
		}
		ctx := api.WithMeta(r.Context(), m)
		ctx = audit.WithRequestInfo(ctx, audit.RequestInfo{IP: m.IP, UserAgent: m.UserAgent, RequestID: w.Header().Get("X-Request-Id")})
		ctx = api.WithWriter(ctx, w)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate runs the authenticator chain (core 7.1). A refused
// credential is 401, and a refused service token is audited (token.denied).
func authenticate(o HandlerOptions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		p, err := o.Authenticator.Authenticate(r)
		var denied *authn.DeniedError
		switch {
		case errors.As(err, &denied):
			if denied.Kind == "service_token" {
				chain := denied.TenantID
				if chain == "" {
					chain = store.InstanceChain
				}
				if aerr := o.Audit.Record(r.Context(), audit.Event{ChainID: chain, ActorKind: audit.ActorServiceToken, ActorID: denied.TokenID,
					Action: "token.denied", Result: audit.Denied, TargetKind: "service_token", TargetID: denied.TokenID,
					Metadata: map[string]any{"reason": denied.Reason, "path": r.URL.Path}}, nil); aerr != nil {
					o.Logger.Error("audit write failed", "action", "token.denied", "error", aerr.Error())
				}
			}
			api.WriteProblem(w, r, &api.Problem{Status: http.StatusUnauthorized, Code: "unauthorized", Title: "Unauthorized",
				Detail: "the token is invalid, expired, or revoked"}, o.Logger)
			return
		case err != nil:
			api.WriteProblem(w, r, err, o.Logger)
			return
		}
		if p != nil {
			r = r.WithContext(api.WithPrincipal(r.Context(), p))
		}
		next.ServeHTTP(w, r)
	})
}

// Path classes for the gates.
var (
	// publicPaths need no principal.
	publicPaths = []string{
		"/api/v1/setup", "/api/v1/setup/status", "/api/v1/setup/totp",
		"/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/device", "/api/v1/auth/device/token",
		"/api/v1/auth/password-reset",
	}
	invitationPath = regexp.MustCompile(`^/api/v1/auth/invitations/[^/]+(/accept)?$`)
	// mfaPendingPaths are reachable by a session that owes its second factor.
	mfaPendingPaths = []string{
		"/api/v1/me", "/api/v1/auth/mfa/totp", "/api/v1/auth/mfa/recovery", "/api/v1/auth/mfa/webauthn/begin",
		"/api/v1/auth/mfa/webauthn/finish", "/api/v1/me/mfa/totp", "/api/v1/me/mfa/totp/confirm",
		"/api/v1/me/mfa/webauthn/register/begin", "/api/v1/me/mfa/webauthn/register/finish",
	}
	// tokenPaths are the only paths a service token reaches (feature 01 3.8).
	tokenPaths = regexp.MustCompile(`^/api/v1/(me|tenants/[^/]+/projects/[^/]+/environments/[^/]+/secrets(/.*)?)$`)
)

func isPublic(p string) bool {
	for _, x := range publicPaths {
		if p == x {
			return true
		}
	}
	return invitationPath.MatchString(p)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// gates enforce, in order: setup (core 10), CSRF (core 7.3), service token
// reach, authentication, and MFA (core 7.2).
func gates(o HandlerOptions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean(r.URL.Path)
		if !strings.HasPrefix(p, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		fail := func(status int, code, detail string) {
			api.WriteProblem(w, r, &api.Problem{Status: status, Code: code, Title: http.StatusText(status), Detail: detail}, o.Logger)
		}
		if !o.API.SetupDone() && !strings.HasPrefix(p, "/api/v1/setup") {
			fail(http.StatusForbidden, "setup_required", "complete first-run setup")
			return
		}
		// Browser mutations must carry the custom header; a cross-site form
		// cannot set it, and SameSite=Strict keeps the cookie at home.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions &&
			!strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "bearer ") &&
			r.Header.Get("X-Rypt-Store-Request") != "1" {
			fail(http.StatusForbidden, "csrf_header_required", "send the X-Rypt-Store-Request: 1 header")
			return
		}
		pr := api.PrincipalFrom(r.Context())
		if pr != nil && pr.Kind == authz.KindServiceToken && !tokenPaths.MatchString(p) {
			fail(http.StatusNotFound, "not_found", "no such endpoint")
			return
		}
		if isPublic(p) {
			next.ServeHTTP(w, r)
			return
		}
		if pr == nil {
			fail(http.StatusUnauthorized, "unauthorized", "sign in first")
			return
		}
		if pr.Kind == authz.KindUser && pr.Session != nil && !pr.Session.MFASatisfied && !contains(mfaPendingPaths, p) {
			mfa, err := o.API.MFAState(r.Context(), pr.ID)
			if err != nil {
				api.WriteProblem(w, r, err, o.Logger)
				return
			}
			if mfa.Any() {
				fail(http.StatusForbidden, "mfa_required", "verify your second factor first")
			} else {
				fail(http.StatusForbidden, "mfa_enrollment_required", "set up an authenticator app or a passkey first")
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- SPA ----

const placeholderPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>rypt-store</title></head>
<body><p>rypt-store is running, but the web interface was not built into this binary. Run <code>make build</code>.</p></body></html>`

// spaHandler serves the embedded build, falling back to index.html for
// client-side routes.
func spaHandler(dist fs.FS) http.Handler {
	if dist == nil {
		dist = emptyFS{}
	}
	files := http.FileServerFS(dist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if fi, err := fs.Stat(dist, name); err == nil && !fi.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		index, err := fs.ReadFile(dist, "index.html")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err != nil {
			_, _ = w.Write([]byte(placeholderPage))
			return
		}
		_, _ = w.Write(index)
	})
}

type emptyFS struct{}

func (emptyFS) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }

// redirectHandler serves the HTTP listener: ACME HTTP-01 challenges when
// given, and a redirect to HTTPS for everything else (core 11).
func redirectHandler(httpsPort string, challenge http.Handler) http.Handler {
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if httpsPort != "" && httpsPort != "443" {
			host = net.JoinHostPort(host, httpsPort)
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	if challenge == nil {
		return redirect
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			challenge.ServeHTTP(w, r)
			return
		}
		redirect.ServeHTTP(w, r)
	})
}
