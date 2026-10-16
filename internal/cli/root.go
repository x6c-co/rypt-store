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
	return exitCode(root.ExecuteContext(ctx), os.Stderr)
}

// exitCode maps a command error to the process exit code.
func exitCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	fmt.Fprintln(stderr, "error:", err)
	return 1
}

// NewRoot builds the command tree with the process environment.
func NewRoot(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	return newRoot(&env{stdin: stdin, stdout: stdout, stderr: stderr, getenv: os.Getenv, cwd: os.Getwd})
}

func newRoot(e *env) *cobra.Command {
	root := &cobra.Command{
		Use:           "rypt-store",
		Short:         "Self-hosted secrets manager",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(e.stdin)
	root.SetOut(e.stdout)
	root.SetErr(e.stderr)
	return addCommands(root, e)
}

// addCommands registers the client commands with the persistent flags.
func addCommands(root *cobra.Command, e *env) *cobra.Command {
	g := &globals{}
	pf := root.PersistentFlags()
	pf.StringVar(&g.server, "server", "", "server URL (overrides .rypt-store.yaml)")
	pf.StringVar(&g.tenant, "tenant", "", "tenant slug")
	pf.StringVar(&g.project, "project", "", "project slug")
	pf.StringVar(&g.environment, "env", "", "environment slug")
	pf.StringVar(&g.output, "output", "text", "output format: text or json")
	pf.StringVar(&g.caFile, "ca-file", "", "PEM file of the CA (or self-signed certificate) to trust")
	pf.BoolVar(&g.insecure, "insecure", false, "skip TLS verification (testing only)")
	root.AddCommand(serverCmd(), loginCmd(e, g), logoutCmd(e, g), initCmd(e, g), secretsCmd(e, g),
		importCmd(e, g), exportCmd(e, g), runCmd(e, g), tokensCmd(e, g), auditCmd(e, g))
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
