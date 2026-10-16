// Package cli implements the rypt-store command line: the server subcommand
// and the CLI client commands (feature 01 section 5).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/x6c-co/rypt-store/internal/server"
	"github.com/x6c-co/rypt-store/internal/version"
)

// exitError carries a specific process exit code (used by `run`).
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// Main runs the command line and returns the process exit code.
func Main(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root := NewRoot(os.Stdin, os.Stdout, os.Stderr)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}

// NewRoot builds the command tree.
func NewRoot(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "rypt-store",
		Short:         "Self-hosted secrets manager",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(serverCmd())
	return root
}

func serverCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the rypt-store server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return server.Run(cmd.Context(), server.Options{
				ConfigPath: configPath,
				Environ:    os.Environ(),
				Stdout:     cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", os.Getenv("RYPT_STORE_CONFIG"), "path to the YAML config file (env RYPT_STORE_CONFIG)")
	return cmd
}
