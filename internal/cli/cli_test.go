package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/x6c-co/rypt-store/internal/server/servertest"
)

func TestMergeEnv(t *testing.T) {
	base := []string{"PATH=/bin", "FOO=orig"}
	got := mergeEnv(base, map[string]string{"FOO": "secret", "BAR": "b"}, false)
	if strings.Join(got, " ") != "PATH=/bin FOO=secret BAR=b" {
		t.Fatalf("override = %v", got)
	}
	got = mergeEnv(base, map[string]string{"FOO": "secret", "BAR": "b"}, true)
	if strings.Join(got, " ") != "PATH=/bin FOO=orig BAR=b" {
		t.Fatalf("keep existing = %v", got)
	}
}

// syncBuffer is a goroutine-safe writer that signals when it sees a string.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) waitFor(t *testing.T, re *regexp.Regexp) []string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(b.String()); m != nil {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s in %q", re, b.String())
	return nil
}

func TestRunExitCodeAndEnv(t *testing.T) {
	var out syncBuffer
	e := &env{stdin: strings.NewReader(""), stdout: &out, stderr: &out}
	code, err := runWithSecrets([]string{"sh", "-c", "exit 7"}, nil, nil, false, e)
	if err != nil || code != 7 {
		t.Fatalf("exit code = %d %v", code, err)
	}
	code, err = runWithSecrets([]string{"sh", "-c", `printf '%s|%s' "$DB" "$KEEP"`}, []string{"KEEP=mine", "DB=old"},
		map[string]string{"DB": "postgres://x", "KEEP": "theirs"}, true, e)
	if err != nil || code != 0 || out.String() != "old|mine" {
		t.Fatalf("keep-existing run = %d %v %q", code, err, out.String())
	}
	if _, err := runWithSecrets([]string{"/nonexistent/binary"}, nil, nil, false, e); err == nil {
		t.Fatal("missing binary did not fail")
	}
}

func TestRunForwardsSignals(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			var out syncBuffer
			e := &env{stdin: strings.NewReader(""), stdout: &out, stderr: &out}
			script := `trap 'echo got; exit 42' TERM HUP INT; echo ready; while true; do sleep 0.05; done`
			done := make(chan int, 1)
			go func() {
				code, _ := runWithSecrets([]string{"sh", "-c", script}, nil, nil, false, e)
				done <- code
			}()
			out.waitFor(t, regexp.MustCompile("ready"))
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			select {
			case code := <-done:
				if code != 42 || !strings.Contains(out.String(), "got") {
					t.Fatalf("child exit = %d, output %q", code, out.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("child did not exit after the forwarded signal")
			}
		})
	}
}

// cliRunner runs the CLI in-process against a test server.
type cliRunner struct {
	t      *testing.T
	server string
	cfg    string
	dir    string
	vars   map[string]string
}

func (c *cliRunner) run(stdin string, args ...string) (string, string, int) {
	c.t.Helper()
	var out, errb syncBuffer
	return c.runWith(&out, &errb, stdin, args...)
}

func (c *cliRunner) runWith(out, errb *syncBuffer, stdin string, args ...string) (string, string, int) {
	vars := map[string]string{"RYPT_STORE_CLI_CONFIG": c.cfg, "RYPT_STORE_INSECURE": "1"}
	for k, v := range c.vars {
		vars[k] = v
	}
	e := &env{stdin: strings.NewReader(stdin), stdout: out, stderr: errb,
		getenv: func(k string) string { return vars[k] }, cwd: func() (string, error) { return c.dir, nil }}
	root := newRoot(e)
	root.SetArgs(args)
	code := exitCode(root.ExecuteContext(context.Background()), errb)
	return out.String(), errb.String(), code
}

func (c *cliRunner) ok(stdin string, args ...string) string {
	c.t.Helper()
	out, errs, code := c.run(stdin, args...)
	if code != 0 {
		c.t.Fatalf("rypt-store %s: exit %d: %s%s", strings.Join(args, " "), code, out, errs)
	}
	return out
}

// TestCLIAcceptance covers feature 01 acceptance criteria 2 and 3 and the
// CLI's credential precedence.
func TestCLIAcceptance(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()
	proj := "/api/v1/tenants/" + a.Tenant + "/projects"
	a.Client.Post(proj, map[string]any{"name": "API"}).Must(t, 201)
	a.Client.Post(proj+"/api/environments/prod/secrets", map[string]any{"name": "DB_URL", "value": "postgres://prod"}).Must(t, 201)

	c := &cliRunner{t: t, server: e.Server.URL, cfg: filepath.Join(t.TempDir(), "cli.yaml"), dir: t.TempDir(), vars: map[string]string{}}

	// login: device flow approved in the browser session.
	var out, errb syncBuffer
	done := make(chan int, 1)
	go func() {
		_, _, code := c.runWith(&out, &errb, "", "login", "--server", e.Server.URL)
		done <- code
	}()
	m := errb.waitFor(t, regexp.MustCompile(`confirm the code ([A-Z]{4}-[A-Z]{4})`))
	a.Client.Post("/api/v1/auth/device/approve", map[string]any{"user_code": m[1], "approve": true}).Must(t, 204)
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("login exit %d: %s %s", code, out.String(), errb.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("login did not finish")
	}
	if fi, err := os.Stat(c.cfg); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("CLI config mode: %v %v", fi, err)
	}

	// init writes the context file without prompts when flags are given.
	c.ok("", "init", "--tenant", a.Tenant, "--project", "api", "--env", "dev")
	ctxBytes, err := os.ReadFile(filepath.Join(c.dir, ContextFile))
	if err != nil || !strings.Contains(string(ctxBytes), "project: api") || strings.Contains(string(ctxBytes), "rsc_") {
		t.Fatalf("context file = %s %v", ctxBytes, err)
	}

	// set (stdin, inline with a warning), get, list, history, restore.
	c.ok("s3cr3t", "secrets", "set", "API_KEY", "--from-stdin", "--comment", "from the CLI")
	_, warn, code := c.run("", "secrets", "set", "API_KEY=second")
	if code != 0 || !strings.Contains(warn, "shell history") {
		t.Fatalf("inline set: %d %q", code, warn)
	}
	if v := c.ok("", "secrets", "get", "API_KEY", "--plain"); v != "second" {
		t.Fatalf("get --plain = %q", v)
	}
	if v := c.ok("", "secrets", "get", "API_KEY", "--version", "1", "--plain"); v != "s3cr3t" {
		t.Fatalf("get --version 1 = %q", v)
	}
	var list []map[string]any
	if err := json.Unmarshal([]byte(c.ok("", "secrets", "list", "--output", "json")), &list); err != nil || len(list) != 1 {
		t.Fatalf("list json = %v %v", list, err)
	}
	if h := c.ok("", "secrets", "history", "API_KEY"); !strings.Contains(h, "VERSION") || strings.Count(h, "\n") != 3 {
		t.Fatalf("history = %q", h)
	}
	c.ok("", "secrets", "restore", "API_KEY", "--version", "1")
	if v := c.ok("", "secrets", "get", "API_KEY", "--plain"); v != "s3cr3t" {
		t.Fatalf("after restore = %q", v)
	}

	// import and export.
	envFile := filepath.Join(c.dir, "local.env")
	if err := os.WriteFile(envFile, []byte("export LOG_LEVEL=debug\nMULTI=\"a\nb\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.ok("", "import", envFile)
	if sh := c.ok("", "export", "--format", "shell"); !strings.Contains(sh, "export LOG_LEVEL='debug'") {
		t.Fatalf("shell export = %q", sh)
	}
	if de := c.ok("", "export"); !strings.Contains(de, `MULTI="a\nb"`) {
		t.Fatalf("dotenv export = %q", de)
	}

	// Acceptance 2: run -- env prints the project's secrets in the child.
	envOut := c.ok("", "run", "--", "env")
	for _, want := range []string{"API_KEY=s3cr3t", "LOG_LEVEL=debug"} {
		if !strings.Contains(envOut, want) {
			t.Fatalf("run -- env lacks %s", want)
		}
	}
	if _, _, code := c.run("", "run", "--", "sh", "-c", "exit 3"); code != 3 {
		t.Fatalf("run exit code = %d", code)
	}

	// Acceptance 3: a CI job with a read token reads prod; a write is 404.
	tok := strings.TrimSpace(c.ok("", "tokens", "create", "--name", "ci", "--env", "prod", "--permission", "read", "--expires", "1d"))
	if !strings.HasPrefix(tok, "rst_") {
		t.Fatalf("token = %q", tok)
	}
	ci := &cliRunner{t: t, server: e.Server.URL, cfg: filepath.Join(t.TempDir(), "none.yaml"), dir: t.TempDir(),
		vars: map[string]string{"RYPT_STORE_TOKEN": tok, "RYPT_STORE_SERVER": e.Server.URL}}
	if v := ci.ok("", "secrets", "get", "DB_URL", "--plain"); v != "postgres://prod" {
		t.Fatalf("ci read = %q", v)
	}
	if _, errs, code := ci.run("", "secrets", "set", "DB_URL=hacked"); code == 0 || !strings.Contains(errs, "HTTP 404") {
		t.Fatalf("ci write: %d %q", code, errs)
	}
	// Precedence: RYPT_STORE_TOKEN beats the CLI session, and its scope
	// fixes tenant and project even against the context file.
	c.vars["RYPT_STORE_TOKEN"] = tok
	if v := c.ok("", "secrets", "get", "DB_URL", "--env", "prod", "--plain"); v != "postgres://prod" {
		t.Fatalf("token over session = %q", v)
	}
	if _, errs, code := c.run("", "secrets", "get", "API_KEY", "--plain"); code == 0 || !strings.Contains(errs, "404") {
		t.Fatalf("token reached dev: %d %q", code, errs)
	}
	delete(c.vars, "RYPT_STORE_TOKEN")

	// Acceptance 4: the chain verifies and the log shows reads and writes.
	if v := c.ok("", "audit", "verify"); !strings.HasPrefix(v, "OK ") {
		t.Fatalf("audit verify = %q", v)
	}
	exp := c.ok("", "audit", "export")
	for _, action := range []string{`"secret.read"`, `"secret.read.bulk"`, `"secret.create"`, `"secret.update"`, `"token.create"`} {
		if !strings.Contains(exp, action) {
			t.Errorf("audit export lacks %s", action)
		}
	}
	if v := c.ok("", "audit", "verify", "--instance"); !strings.HasPrefix(v, "OK ") {
		t.Fatalf("instance verify = %q", v)
	}

	c.ok("", "logout")
	if _, errs, code := c.run("", "secrets", "list"); code == 0 || !strings.Contains(errs, "not signed in") {
		t.Fatalf("after logout: %d %q", code, errs)
	}
}
