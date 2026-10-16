package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/version"
)

// env is the CLI's view of its environment, injectable for tests.
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	cwd    func() (string, error)
}

// globals are the persistent flags.
type globals struct {
	server, tenant, project, environment string
	output                               string
	caFile                               string
	insecure                             bool
}

// session is a resolved CLI invocation: where to connect, with which
// credential, and which tenant, project and environment to act on.
type session struct {
	e       *env
	g       *globals
	cfgPath string
	user    *UserConfig
	ctxFile *ProjectContext
	server  string
	token   string
	service bool // the credential is a service token (RYPT_STORE_TOKEN)
	client  *gen.ClientWithResponses
	scope   *gen.TokenScope
}

func (s *session) json() bool { return s.g.output == "json" }

// out prints a value as JSON or through the text function.
func (s *session) out(v any, text func(w io.Writer)) error {
	if s.json() {
		enc := json.NewEncoder(s.e.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	text(s.e.stdout)
	return nil
}

func (s *session) warn(format string, a ...any) {
	fmt.Fprintf(s.e.stderr, "warning: "+format+"\n", a...)
}

// open resolves config and credentials. needAuth fails without one.
func open(cmd *cobra.Command, e *env, g *globals, needAuth bool) (*session, error) {
	path, err := userConfigPath(e.getenv)
	if err != nil {
		return nil, err
	}
	user, err := loadUserConfig(path)
	if err != nil {
		return nil, err
	}
	dir, err := e.cwd()
	if err != nil {
		return nil, err
	}
	pc, _, err := findContext(dir)
	if err != nil {
		return nil, err
	}
	s := &session{e: e, g: g, cfgPath: path, user: user, ctxFile: pc}
	s.server = firstNonEmpty(g.server, e.getenv("RYPT_STORE_SERVER"), pc.Server, user.Server)
	// A service token wins over the CLI session (feature 01 5.1).
	if t := e.getenv("RYPT_STORE_TOKEN"); t != "" {
		s.token, s.service = t, true
	} else {
		s.token = user.Token
	}
	if s.server == "" {
		return nil, errors.New("no server: run `rypt-store login --server URL`, or set --server or RYPT_STORE_SERVER")
	}
	if needAuth && s.token == "" {
		return nil, errors.New("not signed in: run `rypt-store login`, or set RYPT_STORE_TOKEN")
	}
	if err := s.connect(s.token); err != nil {
		return nil, err
	}
	return s, nil
}

// connect builds the API client for the session's server with token,
// which may be empty for unauthenticated calls.
func (s *session) connect(token string) error {
	hc, err := httpClient(firstNonEmpty(s.g.caFile, s.e.getenv("RYPT_STORE_CA_FILE"), s.user.CAFile),
		s.g.insecure || s.e.getenv("RYPT_STORE_INSECURE") == "1" || s.user.Insecure)
	if err != nil {
		return err
	}
	s.client, err = gen.NewClientWithResponses(strings.TrimRight(s.server, "/"), gen.WithHTTPClient(hc),
		gen.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
			r.Header.Set("User-Agent", "rypt-store-cli/"+version.String())
			if token != "" {
				r.Header.Set("Authorization", "Bearer "+token)
			} else {
				r.Header.Set("X-Rypt-Store-Request", "1")
			}
			return nil
		}))
	return err
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func httpClient(caFile string, insecure bool) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	if insecure {
		cfg.InsecureSkipVerify = true //nolint:gosec // explicit --insecure for self-signed test servers
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

// apiError turns a problem response into an error.
type apiError struct {
	status int
	code   string
	detail string
}

func (e *apiError) Error() string {
	msg := e.detail
	if msg == "" {
		msg = http.StatusText(e.status)
	}
	if e.code != "" {
		return fmt.Sprintf("%s (%s, HTTP %d)", msg, e.code, e.status)
	}
	return fmt.Sprintf("%s (HTTP %d)", msg, e.status)
}

type statusCoder interface{ StatusCode() int }

// check returns nil when a generated response has one of the wanted
// statuses, else the API's problem as an error.
func check(r statusCoder, err error, want ...int) error {
	if err != nil {
		return err
	}
	v := reflect.ValueOf(r)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return errors.New("no response")
		}
		v = v.Elem()
	}
	status := r.StatusCode()
	if slices.Contains(want, status) {
		return nil
	}
	ae := &apiError{status: status}
	var p gen.Problem
	if f := v.FieldByName("Body"); f.IsValid() && json.Unmarshal(f.Bytes(), &p) == nil {
		ae.code, ae.detail = p.Code, deref(p.Detail)
	}
	if ae.code == "mfa_required" || ae.code == "unauthorized" {
		ae.detail += "; run `rypt-store login` again"
	}
	return ae
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// resolveScope fills tenant, project and environment. With a service token
// the token's scope fixes tenant and project (feature 01 5.1).
func (s *session) resolveScope(ctx context.Context, needProject, needEnv bool) (tenant, project, environment string, err error) {
	tenant = firstNonEmpty(s.g.tenant, s.ctxFile.Tenant, s.user.Tenant)
	project = firstNonEmpty(s.g.project, s.ctxFile.Project)
	environment = firstNonEmpty(s.g.environment, s.ctxFile.Environment)
	if s.service {
		r, gerr := s.client.GetMeWithResponse(ctx)
		if err = check(r, gerr, 200); err != nil {
			return
		}
		if r.JSON200.Token == nil {
			err = errors.New("RYPT_STORE_TOKEN is not a service token")
			return
		}
		s.scope = r.JSON200.Token
		tenant, project = s.scope.Tenant, s.scope.Project
		if environment == "" && len(s.scope.Environments) == 1 {
			environment = s.scope.Environments[0]
		}
	}
	switch {
	case tenant == "":
		err = errors.New("no tenant: pass --tenant or run `rypt-store init`")
	case needProject && project == "":
		err = errors.New("no project: pass --project or run `rypt-store init`")
	case needEnv && environment == "":
		err = errors.New("no environment: pass --env or run `rypt-store init`")
	}
	return
}
