package cli

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/x6c-co/rypt-store/internal/api/gen"
)

// parseExpiry accepts an RFC 3339 time or a duration with an optional d
// (days) suffix, such as 90d or 12h.
func parseExpiry(s string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n <= 0 {
			return time.Time{}, fmt.Errorf("invalid expiry %q", s)
		}
		return now.Add(time.Duration(n) * 24 * time.Hour), nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil || dur <= 0 {
		return time.Time{}, fmt.Errorf("invalid expiry %q: use 90d, 12h, or an RFC 3339 time", s)
	}
	return now.Add(dur), nil
}

func tokensCmd(e *env, g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "tokens", Short: "Manage the project's service tokens"}
	project := func(cmd *cobra.Command) (*session, string, string, error) {
		s, err := open(cmd, e, g, true)
		if err != nil {
			return nil, "", "", err
		}
		if s.service {
			return nil, "", "", errors.New("managing tokens needs a user login, not RYPT_STORE_TOKEN")
		}
		t, p, _, err := s.resolveScope(cmd.Context(), true, false)
		return s, t, p, err
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List tokens",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, t, p, err := project(cmd)
			if err != nil {
				return err
			}
			r, err := s.client.ListServiceTokensWithResponse(cmd.Context(), t, p)
			if err := check(r, err, 200); err != nil {
				return err
			}
			ts := r.JSON200.Tokens
			return s.out(ts, func(w io.Writer) {
				tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tNAME\tPREFIX\tPERMISSION\tENVIRONMENTS\tEXPIRES\tSTATUS")
				for _, x := range ts {
					status := "active"
					switch {
					case x.RevokedAt != nil:
						status = "revoked"
					case time.Now().After(x.ExpiresAt):
						status = "expired"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", x.Id, x.Name, x.Prefix, x.Permission,
						strings.Join(x.Environments, ","), when(x.ExpiresAt), status)
				}
				tw.Flush()
			})
		},
	})
	var name, perm, expires string
	var envs []string
	create := &cobra.Command{
		Use:   "create --name NAME --env ENV[,ENV] [--permission read|read_write] [--expires 90d]",
		Short: "Create a token; the token is shown once",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" || len(envs) == 0 {
				return errors.New("--name and --env are required")
			}
			exp, err := parseExpiry(expires, time.Now())
			if err != nil {
				return err
			}
			s, t, p, err := project(cmd)
			if err != nil {
				return err
			}
			r, err := s.client.CreateServiceTokenWithResponse(cmd.Context(), t, p, gen.CreateServiceTokenJSONRequestBody{
				Name: name, Environments: envs, Permission: gen.TokenPermission(perm), ExpiresAt: exp.UTC()})
			if err := check(r, err, 201); err != nil {
				return err
			}
			return s.out(r.JSON201, func(w io.Writer) {
				fmt.Fprintf(w, "%s\n", r.JSON201.Secret)
				fmt.Fprintf(e.stderr, "This token is shown once. It expires %s.\n", when(r.JSON201.Token.ExpiresAt))
			})
		},
	}
	create.Flags().StringVar(&name, "name", "", "label, unique in the project")
	create.Flags().StringSliceVar(&envs, "env", nil, "environments the token reaches")
	create.Flags().StringVar(&perm, "permission", "read", "read or read_write")
	create.Flags().StringVar(&expires, "expires", "90d", "expiry: a duration such as 90d or an RFC 3339 time")
	cmd.AddCommand(create)
	cmd.AddCommand(&cobra.Command{
		Use:   "revoke ID",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, t, p, err := project(cmd)
			if err != nil {
				return err
			}
			r, err := s.client.RevokeServiceTokenWithResponse(cmd.Context(), t, p, args[0])
			if err := check(r, err, 204); err != nil {
				return err
			}
			return s.out(map[string]any{"revoked": args[0]}, func(w io.Writer) { fmt.Fprintf(w, "Revoked token %s.\n", args[0]) })
		},
	})
	return cmd
}

func auditCmd(e *env, g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Verify and export the audit log"}
	var instance bool
	chain := func(cmd *cobra.Command) (*session, string, error) {
		s, err := open(cmd, e, g, true)
		if err != nil {
			return nil, "", err
		}
		if instance {
			return s, "", nil
		}
		t, _, _, err := s.resolveScope(cmd.Context(), false, false)
		return s, t, err
	}
	verify := &cobra.Command{
		Use:   "verify [--tenant SLUG | --instance]",
		Short: "Walk a chain and report OK <seq> <hash> or the first broken link",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, tenant, err := chain(cmd)
			if err != nil {
				return err
			}
			var v *gen.AuditVerify
			if tenant == "" {
				r, err := s.client.VerifyInstanceAuditWithResponse(cmd.Context())
				if err := check(r, err, 200); err != nil {
					return err
				}
				v = r.JSON200
			} else {
				r, err := s.client.VerifyTenantAuditWithResponse(cmd.Context(), tenant)
				if err := check(r, err, 200); err != nil {
					return err
				}
				v = r.JSON200
			}
			if err := s.out(v, func(w io.Writer) {
				if v.Ok {
					fmt.Fprintf(w, "OK %d %s\n", v.Seq, v.Hash)
				} else {
					fmt.Fprintf(w, "BROKEN at seq %d: %s\n", v.Seq, deref(v.Reason))
				}
			}); err != nil {
				return err
			}
			if !v.Ok {
				return &exitError{code: 2}
			}
			return nil
		},
	}
	verify.Flags().BoolVar(&instance, "instance", false, "verify the instance chain")
	cmd.AddCommand(verify)

	var from, to, outFile string
	export := &cobra.Command{
		Use:   "export [--tenant SLUG | --instance] [--from T] [--to T] [-o FILE]",
		Short: "Export a chain as JSON Lines",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, tenant, err := chain(cmd)
			if err != nil {
				return err
			}
			parse := func(v string) (*time.Time, error) {
				if v == "" {
					return nil, nil
				}
				t, err := time.Parse(time.RFC3339, v)
				return &t, err
			}
			f, err := parse(from)
			if err != nil {
				return err
			}
			tt, err := parse(to)
			if err != nil {
				return err
			}
			// The raw client streams the JSON Lines instead of decoding them.
			var resp *http.Response
			if tenant == "" {
				resp, err = s.client.ClientInterface.ExportInstanceAudit(cmd.Context(), &gen.ExportInstanceAuditParams{From: f, To: tt})
			} else {
				resp, err = s.client.ClientInterface.ExportTenantAudit(cmd.Context(), tenant, &gen.ExportTenantAuditParams{From: f, To: tt})
			}
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(resp.Body)
				return check(&rawResponse{status: resp.StatusCode, Body: b}, nil, http.StatusOK)
			}
			w := e.stdout
			if outFile != "" && outFile != "-" {
				f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			_, err = io.Copy(w, resp.Body)
			return err
		},
	}
	export.Flags().BoolVar(&instance, "instance", false, "export the instance chain")
	export.Flags().StringVar(&from, "from", "", "RFC 3339 start time")
	export.Flags().StringVar(&to, "to", "", "RFC 3339 end time")
	export.Flags().StringVarP(&outFile, "output-file", "o", "", "write to a file instead of standard output")
	cmd.AddCommand(export)
	return cmd
}

// rawResponse adapts a plain HTTP response to check.
type rawResponse struct {
	status int
	Body   []byte
}

func (r *rawResponse) StatusCode() int { return r.status }
