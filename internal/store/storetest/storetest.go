// Package storetest starts a throwaway rqlite node for integration tests.
//
// It looks for an rqlited binary, in order: $RYPT_STORE_TEST_RQLITED, the
// repository's .tools/rqlite directory (see `make tools`), and $PATH. With no
// binary it runs the official rqlite/rqlite image through testcontainers-go
// when Docker is available. Otherwise the test is skipped with a message
// that says how to provide rqlite, never passed vacuously.
package storetest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/x6c-co/rypt-store/internal/store/rqlite"
)

// RQLiteImage is the image used when no local binary is found.
const RQLiteImage = "rqlite/rqlite:10.6.0"

// New returns a migrated store on a fresh rqlite node that is stopped when
// the test ends.
func New(t testing.TB) *rqlite.Store {
	t.Helper()
	url := StartRQLite(t)
	s, err := rqlite.Open(url, "", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// StartRQLite starts a node and returns its HTTP URL.
func StartRQLite(t testing.TB) string {
	t.Helper()
	if bin := findBinary(); bin != "" {
		return startBinary(t, bin)
	}
	if url, ok := startContainer(t); ok {
		return url
	}
	t.Skip("rqlite is not available: run `make tools` to download rqlited into .tools/, set RYPT_STORE_TEST_RQLITED, or start Docker")
	return ""
}

func findBinary() string {
	if p := os.Getenv("RYPT_STORE_TEST_RQLITED"); p != "" {
		return p
	}
	if root := repoRoot(); root != "" {
		matches, _ := filepath.Glob(filepath.Join(root, ".tools", "rqlite", "*", "rqlited"))
		if len(matches) > 0 {
			return matches[len(matches)-1]
		}
	}
	if p, err := exec.LookPath("rqlited"); err == nil {
		return p
	}
	return ""
}

func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	// internal/store/storetest/storetest.go -> repository root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func freePort(t testing.TB) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startBinary(t testing.TB, bin string) string {
	t.Helper()
	dir := t.TempDir()
	var lastErr error
	for range 3 {
		httpAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
		raftAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
		node := filepath.Join(dir, fmt.Sprintf("node-%d", time.Now().UnixNano()))
		logf, err := os.Create(node + ".log")
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "-http-addr", httpAddr, "-raft-addr", raftAddr, node)
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			t.Fatalf("start rqlited: %v", err)
		}
		url := "http://" + httpAddr
		if err := waitReady(url, 20*time.Second); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			logf.Close()
			lastErr = err
			continue
		}
		t.Cleanup(func() {
			_ = cmd.Process.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
			logf.Close()
		})
		return url
	}
	t.Fatalf("rqlited did not become ready: %v", lastErr)
	return ""
}

func waitReady(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("%s/readyz not ready after %s", url, timeout)
}

func startContainer(t testing.TB) (url string, ok bool) {
	t.Helper()
	if os.Getenv("RYPT_STORE_TEST_NO_DOCKER") != "" {
		return "", false
	}
	// The client constructor queries the daemon, so it fails fast without one.
	cli, err := testcontainers.NewDockerClientWithOpts(context.Background())
	if err != nil {
		return "", false
	}
	_ = cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := testcontainers.Run(ctx, RQLiteImage,
		testcontainers.WithExposedPorts("4001/tcp"),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/readyz").WithPort("4001/tcp").WithStartupTimeout(time.Minute)),
	)
	if err != nil {
		t.Logf("rqlite container unavailable: %v", err)
		return "", false
	}
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(c) })
	endpoint, err := c.PortEndpoint(ctx, "4001/tcp", "http")
	if err != nil {
		t.Fatalf("rqlite container endpoint: %v", err)
	}
	return endpoint, true
}
