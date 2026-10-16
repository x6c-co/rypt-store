// Package server wires the rypt-store server process (core 4.1).
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/x6c-co/rypt-store/internal/config"
	"github.com/x6c-co/rypt-store/internal/logging"
	"github.com/x6c-co/rypt-store/internal/store/rqlite"
	"github.com/x6c-co/rypt-store/internal/tlsmgr"
	"github.com/x6c-co/rypt-store/internal/version"
	"github.com/x6c-co/rypt-store/web"
)

// Options configures Run.
type Options struct {
	ConfigPath string
	Environ    []string
	// Stdout receives the logs and the one-time setup token block.
	Stdout io.Writer
	// Ready, when set, receives the bound HTTPS address once listening.
	Ready func(addr string)
}

// Run starts the server and blocks until ctx ends.
func Run(ctx context.Context, opts Options) error {
	cfg, err := config.Load(opts.ConfigPath, opts.Environ)
	if err != nil {
		return err
	}
	log := logging.New(opts.Stdout, slog.LevelInfo)
	log.Info("starting rypt-store", "version", version.String(), "provider", cfg.Keys.Provider, "tls_mode", cfg.EffectiveTLSMode())

	db, err := rqlite.Open(cfg.Database.URL, cfg.Database.Username, cfg.Database.Password)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := waitForDatabase(ctx, db, log); err != nil {
		return err
	}
	if err := db.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	app, err := NewApp(ctx, AppOptions{Config: cfg, Store: db, SPA: web.Dist(), Logger: log})
	if err != nil {
		return err
	}
	tm, err := tlsmgr.New(cfg, log)
	if err != nil {
		return err
	}
	if !app.API.SetupDone() {
		tok, err := app.API.IssueSetupToken(ctx)
		if err != nil {
			return fmt.Errorf("issue setup token: %w", err)
		}
		printSetupToken(opts.Stdout, cfg, tok)
	}
	return serve(ctx, app, tm, opts)
}

// printSetupToken prints the one-time token in a clearly delimited block
// (core 10). It bypasses the redacting logger on purpose.
func printSetupToken(w io.Writer, cfg *config.Config, tok string) {
	url := cfg.Server.PublicURL
	if url == "" {
		url = "https://<this host>"
	}
	fmt.Fprintf(w, `
================================================================================
 rypt-store first-run setup

 Setup token (valid for 24 hours; a restart before setup issues a new one):

     %s

 Open %s and enter the token in the setup wizard.
================================================================================

`, tok, url)
}

func serve(ctx context.Context, app *App, tm *tlsmgr.Manager, opts Options) error {
	cfg, log := app.Config, app.Log
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := tm.Start(ctx); err != nil {
		return fmt.Errorf("start TLS: %w", err)
	}

	errc := make(chan error, 3)
	var servers []*http.Server
	listen := func(name, addr string, h http.Handler, tlsOn bool) error {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s listener on %s: %w", name, addr, err)
		}
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
			ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
		servers = append(servers, srv)
		log.Info("listening", "listener", name, "addr", ln.Addr().String())
		go func() {
			var err error
			if tlsOn {
				srv.TLSConfig = tm.TLSConfig
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s server: %w", name, err)
			}
		}()
		if name == "https" && opts.Ready != nil {
			opts.Ready(ln.Addr().String())
		}
		return nil
	}

	if err := listen("https", cfg.Server.HTTPSListen, app.Handler, true); err != nil {
		return err
	}
	if cfg.Server.HTTPListen != "" {
		_, httpsPort, _ := net.SplitHostPort(cfg.Server.HTTPSListen)
		if cfg.Server.PublicURL != "" {
			httpsPort = "443"
		}
		if err := listen("http", cfg.Server.HTTPListen, tm.ChallengeHandler(redirectHandler(httpsPort, nil)), false); err != nil {
			return err
		}
	}
	if cfg.Metrics.Listen != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(app.Metrics.Registry, promhttp.HandlerOpts{}))
		if err := listen("metrics", cfg.Metrics.Listen, mux, false); err != nil {
			return err
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		app.Jobs.Run(ctx)
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	log.Info("shutting down")
	shutdown, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	cancel()
	wg.Wait()
	_ = app.Keys.FlushOpCounts(shutdown)
	return runErr
}

// waitForDatabase retries the first connection, since compose may start the
// server before rqlite is ready.
func waitForDatabase(ctx context.Context, db *rqlite.Store, log *slog.Logger) error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		err := db.Ping(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("database not reachable: %w", err)
		}
		log.Warn("waiting for database", "error", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
