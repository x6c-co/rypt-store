// Package server wires the rypt-store server process (core 4.1).
package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/x6c-co/rypt-store/internal/config"
	"github.com/x6c-co/rypt-store/internal/logging"
	"github.com/x6c-co/rypt-store/internal/store/rqlite"
)

// Options configures Run.
type Options struct {
	ConfigPath string
	Environ    []string
	// Stdout receives the logs and the one-time setup token block.
	Stdout io.Writer
}

// Run starts the server and blocks until ctx ends.
func Run(ctx context.Context, opts Options) error {
	cfg, err := config.Load(opts.ConfigPath, opts.Environ)
	if err != nil {
		return err
	}
	log := logging.New(opts.Stdout, slog.LevelInfo)

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
	log.Info("database ready", "url", cfg.Database.URL)
	<-ctx.Done()
	return nil
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
