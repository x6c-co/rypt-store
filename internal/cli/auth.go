package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/x6c-co/rypt-store/internal/api/gen"
)

func loginCmd(e *env, g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Sign in through the browser (device flow) and store a CLI session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := open(cmd, e, g, false)
			if err != nil {
				return err
			}
			// The device flow runs without any stored credential.
			if err := s.connect(""); err != nil {
				return err
			}
			ctx := cmd.Context()
			host, _ := os.Hostname()
			start, err := s.client.StartDeviceAuthWithResponse(ctx, gen.StartDeviceAuthJSONRequestBody{ClientName: ptr("rypt-store CLI on " + host)})
			if err := check(start, err, 200); err != nil {
				return err
			}
			d := start.JSON200
			fmt.Fprintf(e.stderr, "Open %s\nand confirm the code %s\n\nWaiting for approval...\n", d.VerificationUriComplete, d.UserCode)
			interval := time.Duration(max(d.Interval, 1)) * time.Second
			deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(interval):
				}
				r, err := s.client.PollDeviceTokenWithResponse(ctx, gen.PollDeviceTokenJSONRequestBody{DeviceCode: d.DeviceCode})
				err = check(r, err, 200)
				if err == nil {
					s.user.Server, s.user.Token = s.server, r.JSON200.AccessToken
					s.user.CAFile = firstNonEmpty(g.caFile, s.user.CAFile)
					s.user.Insecure = g.insecure || s.user.Insecure
					if err := saveUserConfig(s.cfgPath, s.user); err != nil {
						return err
					}
					fmt.Fprintf(e.stdout, "Signed in to %s. The CLI session is stored in %s.\n", s.server, s.cfgPath)
					return nil
				}
				var ae *apiError
				if !errors.As(err, &ae) {
					return err
				}
				switch ae.code {
				case "authorization_pending":
				case "slow_down":
					interval += 5 * time.Second
				default:
					return err
				}
			}
			return errors.New("the code expired before it was approved; run login again")
		},
	}
}

func ptr[T any](v T) *T { return &v }

func logoutCmd(e *env, g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "End the CLI session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := open(cmd, e, g, false)
			if err != nil {
				return err
			}
			if s.user.Token == "" {
				fmt.Fprintln(e.stdout, "Not signed in.")
				return nil
			}
			if !s.service {
				r, err := s.client.LogoutWithResponse(cmd.Context())
				if err := check(r, err, 204, 401); err != nil {
					s.warn("the server did not confirm the logout: %v", err)
				}
			}
			s.user.Token = ""
			if err := saveUserConfig(s.cfgPath, s.user); err != nil {
				return err
			}
			fmt.Fprintln(e.stdout, "Signed out.")
			return nil
		},
	}
}

// choose prompts for one of options, or takes the only one.
func choose(in *bufio.Reader, out io.Writer, what string, options []string, current string) (string, error) {
	if len(options) == 0 {
		return "", fmt.Errorf("there are no %ss to choose from", what)
	}
	if len(options) == 1 {
		fmt.Fprintf(out, "%s: %s\n", what, options[0])
		return options[0], nil
	}
	fmt.Fprintf(out, "Choose a %s:\n", what)
	def := 1
	for i, o := range options {
		if o == current {
			def = i + 1
		}
		fmt.Fprintf(out, "  %d) %s\n", i+1, o)
	}
	fmt.Fprintf(out, "%s [%d]: ", what, def)
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no answer")
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return options[def-1], nil
	}
	if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(options) {
		return options[n-1], nil
	}
	for _, o := range options {
		if o == line {
			return o, nil
		}
	}
	return "", fmt.Errorf("%q is not one of the choices", line)
}

func initCmd(e *env, g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Write .rypt-store.yaml for this directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := open(cmd, e, g, true)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			in := bufio.NewReader(e.stdin)
			pc := &ProjectContext{Server: s.server}
			tenant, project, environment, err := initChoices(ctx, s, in)
			if err != nil {
				return err
			}
			pc.Tenant, pc.Project, pc.Environment = tenant, project, environment
			dir, err := e.cwd()
			if err != nil {
				return err
			}
			path := dir + string(os.PathSeparator) + ContextFile
			if err := writeContext(path, pc); err != nil {
				return err
			}
			s.user.Tenant = tenant
			if !s.service {
				_ = saveUserConfig(s.cfgPath, s.user)
			}
			fmt.Fprintf(e.stdout, "Wrote %s (%s / %s / %s).\n", path, tenant, project, environment)
			return nil
		},
	}
}

func initChoices(ctx context.Context, s *session, in *bufio.Reader) (string, string, string, error) {
	out := s.e.stderr
	if s.service {
		t, p, env, err := s.resolveScope(ctx, true, false)
		if err != nil {
			return "", "", "", err
		}
		if env == "" {
			if env, err = choose(in, out, "environment", s.scope.Environments, ""); err != nil {
				return "", "", "", err
			}
		}
		return t, p, env, nil
	}
	tenant := s.g.tenant
	if tenant == "" {
		r, err := s.client.ListTenantsWithResponse(ctx, &gen.ListTenantsParams{})
		if err := check(r, err, 200); err != nil {
			return "", "", "", err
		}
		var slugs []string
		for _, t := range r.JSON200.Tenants {
			slugs = append(slugs, t.Slug)
		}
		if tenant, err = choose(in, out, "tenant", slugs, s.user.Tenant); err != nil {
			return "", "", "", err
		}
	}
	r, err := s.client.ListProjectsWithResponse(ctx, tenant)
	if err := check(r, err, 200); err != nil {
		return "", "", "", err
	}
	project := s.g.project
	var envs []string
	if project == "" {
		var slugs []string
		for _, p := range r.JSON200.Projects {
			slugs = append(slugs, p.Slug)
		}
		if project, err = choose(in, out, "project", slugs, ""); err != nil {
			return "", "", "", err
		}
	}
	for _, p := range r.JSON200.Projects {
		if p.Slug == project {
			for _, en := range p.Environments {
				envs = append(envs, en.Slug)
			}
		}
	}
	if len(envs) == 0 {
		return "", "", "", fmt.Errorf("project %s not found in %s", project, tenant)
	}
	environment := s.g.environment
	if environment == "" {
		if environment, err = choose(in, out, "environment", envs, "dev"); err != nil {
			return "", "", "", err
		}
	}
	return tenant, project, environment, nil
}
