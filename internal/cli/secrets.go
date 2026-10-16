package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/secrets"
)

// envSession opens a session scoped to an environment.
func envSession(cmd *cobra.Command, e *env, g *globals) (*session, string, string, string, error) {
	s, err := open(cmd, e, g, true)
	if err != nil {
		return nil, "", "", "", err
	}
	t, p, en, err := s.resolveScope(cmd.Context(), true, true)
	return s, t, p, en, err
}

func when(t time.Time) string { return t.Local().Format("2006-01-02 15:04") }

// listAll pages through an environment's secrets (names, no values).
func listAll(ctx context.Context, s *session, t, p, en string) ([]gen.Secret, error) {
	var out []gen.Secret
	var cursor *string
	for {
		r, err := s.client.ListSecretsWithResponse(ctx, t, p, en, &gen.ListSecretsParams{Limit: ptr(500), Cursor: cursor})
		if err := check(r, err, 200); err != nil {
			return nil, err
		}
		out = append(out, r.JSON200.Secrets...)
		if r.JSON200.NextCursor == nil {
			return out, nil
		}
		cursor = r.JSON200.NextCursor
	}
}

// findSecret resolves a secret name, or an ID, to the live secret. Names
// cannot contain "-", so a UUID argument is never a name.
func findSecret(ctx context.Context, s *session, t, p, en, ref string) (*gen.Secret, error) {
	if id, err := uuid.Parse(ref); err == nil {
		return &gen.Secret{Id: id.String()}, nil
	}
	r, err := s.client.ListSecretsWithResponse(ctx, t, p, en, &gen.ListSecretsParams{Name: &ref})
	if err := check(r, err, 200); err != nil {
		return nil, err
	}
	if len(r.JSON200.Secrets) == 0 {
		return nil, fmt.Errorf("no secret named %s in %s", ref, en)
	}
	return &r.JSON200.Secrets[0], nil
}

// secretID resolves a name or ID to the API's path parameter.
func secretID(ctx context.Context, s *session, t, p, en, ref string) (gen.SecretId, error) {
	x, err := findSecret(ctx, s, t, p, en, ref)
	if err != nil {
		return gen.SecretId{}, err
	}
	return uuid.Parse(x.Id)
}

func secretsCmd(e *env, g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "secrets", Short: "Read and change secrets"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List names, versions and update times (no values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, t, p, en, err := envSession(cmd, e, g)
			if err != nil {
				return err
			}
			xs, err := listAll(cmd.Context(), s, t, p, en)
			if err != nil {
				return err
			}
			return s.out(xs, func(w io.Writer) {
				tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "NAME\tVERSION\tUPDATED\tBY")
				for _, x := range xs {
					by := ""
					if x.UpdatedBy != nil {
						by = firstNonEmpty(deref(x.UpdatedBy.Display), x.UpdatedBy.Id)
					}
					fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", x.Name, x.Version, when(x.UpdatedAt), by)
				}
				tw.Flush()
			})
		},
	})

	var version int
	var plain bool
	get := &cobra.Command{
		Use:   "get NAME|ID",
		Short: "Print a secret's value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, t, p, en, err := envSession(cmd, e, g)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			id, err := secretID(ctx, s, t, p, en, args[0])
			if err != nil {
				return err
			}
			var value string
			var shown any
			if version > 0 {
				r, err := s.client.GetSecretVersionWithResponse(ctx, t, p, en, id, version)
				if err := check(r, err, 200); err != nil {
					return err
				}
				value, shown = r.JSON200.Value, r.JSON200
			} else {
				r, err := s.client.GetSecretWithResponse(ctx, t, p, en, id)
				if err := check(r, err, 200); err != nil {
					return err
				}
				value, shown = r.JSON200.Value, r.JSON200
			}
			if plain {
				_, err := io.WriteString(e.stdout, value)
				return err
			}
			return s.out(shown, func(w io.Writer) {
				tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "NAME\tVALUE")
				fmt.Fprintf(tw, "%s\t%s\n", args[0], value)
				tw.Flush()
			})
		},
	}
	get.Flags().IntVar(&version, "version", 0, "read an older version")
	get.Flags().BoolVar(&plain, "plain", false, "print only the value, with no trailing newline")
	cmd.AddCommand(get)

	var fromFile, comment string
	var fromStdin bool
	set := &cobra.Command{
		Use:   "set NAME [--from-file PATH | --from-stdin] | NAME=VALUE",
		Short: "Create or update a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, t, p, en, err := envSession(cmd, e, g)
			if err != nil {
				return err
			}
			name, value, inline := strings.Cut(args[0], "=")
			switch {
			case inline && (fromFile != "" || fromStdin):
				return errors.New("give the value inline or with --from-file/--from-stdin, not both")
			case inline:
				s.warn("the value is now in your shell history; prefer --from-stdin or --from-file")
			case fromFile != "":
				b, err := os.ReadFile(fromFile)
				if err != nil {
					return err
				}
				value = string(b)
			case fromStdin:
				b, err := io.ReadAll(e.stdin)
				if err != nil {
					return err
				}
				value = string(b)
			default:
				if value, err = promptValue(e, name); err != nil {
					return err
				}
			}
			var c *string
			if cmd.Flags().Changed("comment") {
				c = &comment
			}
			ver, err := setSecret(cmd.Context(), s, t, p, en, name, value, c)
			if err != nil {
				return err
			}
			return s.out(map[string]any{"name": name, "version": ver}, func(w io.Writer) {
				fmt.Fprintf(w, "Saved %s (version %d) in %s.\n", name, ver, en)
			})
		},
	}
	set.Flags().StringVar(&fromFile, "from-file", "", "read the value from a file")
	set.Flags().BoolVar(&fromStdin, "from-stdin", false, "read the value from standard input")
	set.Flags().StringVar(&comment, "comment", "", "plaintext note (not encrypted)")
	cmd.AddCommand(set)

	cmd.AddCommand(&cobra.Command{
		Use:   "delete NAME|ID",
		Short: "Delete a secret (restorable until purged)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, t, p, en, err := envSession(cmd, e, g)
			if err != nil {
				return err
			}
			id, err := secretID(cmd.Context(), s, t, p, en, args[0])
			if err != nil {
				return err
			}
			r, err := s.client.DeleteSecretWithResponse(cmd.Context(), t, p, en, id)
			if err := check(r, err, 204); err != nil {
				return err
			}
			return s.out(map[string]any{"deleted": args[0]}, func(w io.Writer) { fmt.Fprintf(w, "Deleted %s from %s.\n", args[0], en) })
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "history NAME|ID",
		Short: "List a secret's versions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, t, p, en, err := envSession(cmd, e, g)
			if err != nil {
				return err
			}
			id, err := secretID(cmd.Context(), s, t, p, en, args[0])
			if err != nil {
				return err
			}
			r, err := s.client.ListSecretVersionsWithResponse(cmd.Context(), t, p, en, id)
			if err := check(r, err, 200); err != nil {
				return err
			}
			vs := r.JSON200.Versions
			return s.out(vs, func(w io.Writer) {
				tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "VERSION\tCREATED\tBY\tRESTORED FROM")
				for _, v := range vs {
					from := ""
					if v.RestoredFrom != nil {
						from = fmt.Sprint(*v.RestoredFrom)
					}
					fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", v.Version, when(v.CreatedAt), firstNonEmpty(deref(v.CreatedBy.Display), v.CreatedBy.Id), from)
				}
				tw.Flush()
			})
		},
	})

	var restoreVersion int
	restore := &cobra.Command{
		Use:   "restore NAME|ID --version N",
		Short: "Write an old version's value as a new version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if restoreVersion < 1 {
				return errors.New("--version is required")
			}
			s, t, p, en, err := envSession(cmd, e, g)
			if err != nil {
				return err
			}
			id, err := secretID(cmd.Context(), s, t, p, en, args[0])
			if err != nil {
				return err
			}
			r, err := s.client.RestoreSecretVersionWithResponse(cmd.Context(), t, p, en, id, restoreVersion)
			if err := check(r, err, 200); err != nil {
				return err
			}
			return s.out(r.JSON200, func(w io.Writer) {
				fmt.Fprintf(w, "Restored version %d of %s as version %d.\n", restoreVersion, args[0], r.JSON200.Version)
			})
		},
	}
	restore.Flags().IntVar(&restoreVersion, "version", 0, "the version to restore")
	cmd.AddCommand(restore)
	return cmd
}

func promptValue(e *env, name string) (string, error) {
	if f, ok := e.stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(e.stderr, "Value for %s (input hidden): ", name)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(e.stderr)
		return string(b), err
	}
	b, err := io.ReadAll(e.stdin)
	return string(b), err
}

// setSecret creates the secret or updates it against its current version.
func setSecret(ctx context.Context, s *session, t, p, en, name, value string, comment *string) (int, error) {
	r, err := s.client.ListSecretsWithResponse(ctx, t, p, en, &gen.ListSecretsParams{Name: &name})
	if err := check(r, err, 200); err != nil {
		return 0, err
	}
	if len(r.JSON200.Secrets) == 1 {
		x := r.JSON200.Secrets[0]
		id, err := uuid.Parse(x.Id)
		if err != nil {
			return 0, err
		}
		u, err := s.client.UpdateSecretWithResponse(ctx, t, p, en, id, &gen.UpdateSecretParams{IfMatch: secrets.ETag(x.Version)},
			gen.UpdateSecretJSONRequestBody{Value: value, Comment: comment})
		if err := check(u, err, 200); err != nil {
			return 0, err
		}
		return u.JSON200.Version, nil
	}
	c, err := s.client.CreateSecretWithResponse(ctx, t, p, en, gen.CreateSecretJSONRequestBody{Name: name, Value: value, Comment: comment})
	if err := check(c, err, 201); err != nil {
		return 0, err
	}
	return c.JSON201.Version, nil
}

func importCmd(e *env, g *globals) *cobra.Command {
	var overwrite bool
	cmd := &cobra.Command{
		Use:   "import FILE",
		Short: "Import a .env file into the environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, t, p, en, err := envSession(cmd, e, g)
			if err != nil {
				return err
			}
			var src []byte
			if args[0] == "-" {
				src, err = io.ReadAll(e.stdin)
			} else {
				src, err = os.ReadFile(args[0])
			}
			if err != nil {
				return err
			}
			mode := gen.SkipExisting
			if overwrite {
				mode = gen.Overwrite
			}
			r, err := s.client.ImportSecretsWithTextBodyWithResponse(cmd.Context(), t, p, en, &gen.ImportSecretsParams{Mode: &mode}, string(src))
			if err := check(r, err, 200); err != nil {
				return err
			}
			res := r.JSON200
			return s.out(res, func(w io.Writer) {
				fmt.Fprintf(w, "Created %d, updated %d, skipped %d, rejected %d.\n", len(res.Created), len(res.Updated), len(res.Skipped), len(res.Rejected))
				for _, x := range res.Rejected {
					fmt.Fprintf(w, "  line %d: %s %s\n", x.Line, deref(x.Name), x.Reason)
				}
			})
		},
	}
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite existing secrets")
	return cmd
}

// fetchValues reads every value of the environment in one bulk read.
func fetchValues(ctx context.Context, s *session, t, p, en string) (map[string]string, error) {
	r, err := s.client.GetSecretValuesWithResponse(ctx, t, p, en)
	if err := check(r, err, 200); err != nil {
		return nil, err
	}
	return r.JSON200.Values, nil
}

func exportCmd(e *env, g *globals) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print every value of the environment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, t, p, en, err := envSession(cmd, e, g)
			if err != nil {
				return err
			}
			values, err := fetchValues(cmd.Context(), s, t, p, en)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				g2 := *s.g
				g2.output = "json"
				s.g = &g2
				return s.out(values, nil)
			case "shell":
				_, err = io.WriteString(e.stdout, secrets.FormatShell(values))
			case "dotenv":
				_, err = io.WriteString(e.stdout, secrets.FormatDotenv(values))
			default:
				return fmt.Errorf("--format must be dotenv, json, or shell")
			}
			return err
		},
	}
	cmd.Flags().StringVar(&format, "format", "dotenv", "dotenv, json, or shell")
	return cmd
}

func runCmd(e *env, g *globals) *cobra.Command {
	var keep bool
	cmd := &cobra.Command{
		Use:   "run [--keep-existing] -- COMMAND [ARGS...]",
		Short: "Run a command with the environment's secrets in its environment",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, t, p, en, err := envSession(cmd, e, g)
			if err != nil {
				return err
			}
			values, err := fetchValues(cmd.Context(), s, t, p, en)
			if err != nil {
				return err
			}
			code, err := runWithSecrets(args, os.Environ(), values, keep, e)
			if err != nil {
				return err
			}
			if code != 0 {
				return &exitError{code: code}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&keep, "keep-existing", false, "do not override variables already set")
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// mergeEnv adds values to base; values override unless keep is set.
func mergeEnv(base []string, values map[string]string, keep bool) []string {
	present := map[string]int{}
	out := make([]string, 0, len(base)+len(values))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		present[k] = len(out)
		out = append(out, kv)
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		kv := n + "=" + values[n]
		if i, ok := present[n]; ok {
			if !keep {
				out[i] = kv
			}
			continue
		}
		out = append(out, kv)
	}
	return out
}

// runWithSecrets starts the child, forwards SIGINT, SIGTERM and SIGHUP to
// it, and returns its exit code (feature 01 5.2). Values never touch disk.
func runWithSecrets(args, base []string, values map[string]string, keep bool, e *env) (int, error) {
	c := exec.Command(args[0], args[1:]...)
	c.Env = mergeEnv(base, values, keep)
	c.Stdin, c.Stdout, c.Stderr = e.stdin, e.stdout, e.stderr
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := c.Start(); err != nil {
		return 0, err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigs:
				_ = c.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	err := c.Wait()
	close(done)
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ee.ExitCode(), nil
	}
	return 0, err
}
