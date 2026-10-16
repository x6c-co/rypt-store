package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/x6c-co/rypt-store/internal/api/gen"
)

func keysCmd(e *env, g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "keys", Short: "Inspect the key provider and run re-wrap migrations (instance admins)"}
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show the provider, wrap counts, and this month's provider operations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := open(cmd, e, g, true)
			if err != nil {
				return err
			}
			r, err := s.client.GetInstanceKeysWithResponse(cmd.Context())
			if err := check(r, err, 200); err != nil {
				return err
			}
			k := r.JSON200
			return s.out(k, func(w io.Writer) {
				fmt.Fprintf(w, "Provider for new wraps: %s\nDefault key mode: %s\n\n", k.Provider, k.DefaultKeyMode)
				tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "PROVIDER\tLOADED\tREACHABLE\tWRAPS")
				for _, p := range k.Providers {
					fmt.Fprintf(tw, "%s\t%v\t%v\t%d\n", p.Name, p.Loaded, !p.Unavailable, p.Wraps)
				}
				tw.Flush()
				fmt.Fprintf(w, "\nOperations in %s (counted locally):\n", k.Month)
				for _, c := range k.OpCounts {
					fmt.Fprintf(w, "  %s %s: %d\n", c.Provider, c.Op, c.Count)
				}
			})
		},
	})

	var to, mode string
	var dryRun, wait bool
	migrate := &cobra.Command{
		Use:   "migrate (--to PROVIDER | --project SLUG --mode A|B|C) [--dry-run] [--wait]",
		Short: "Move every wrap to a provider, or change one project's key mode",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := open(cmd, e, g, true)
			if err != nil {
				return err
			}
			body := gen.KeyMigrationRequest{DryRun: &dryRun}
			switch {
			case to != "" && mode == "":
				body.Kind = gen.KeyMigrationRequestKindProvider
				body.Params = &gen.KeyMigrationParams{To: &to}
			case mode != "" && to == "":
				t, p, _, err := s.resolveScope(cmd.Context(), true, false)
				if err != nil {
					return err
				}
				m := gen.KeyMode(mode)
				body.Kind = gen.KeyMigrationRequestKindMode
				body.Params = &gen.KeyMigrationParams{Tenant: &t, Project: &p, Mode: &m}
			default:
				return errors.New("pass either --to PROVIDER or --mode A|B|C (with --project)")
			}
			return startMigration(cmd.Context(), s, body, wait)
		},
	}
	migrate.Flags().StringVar(&to, "to", "", "target provider (local or rypt)")
	migrate.Flags().StringVar(&mode, "mode", "", "target key mode for --project")
	migrate.Flags().BoolVar(&dryRun, "dry-run", false, "report the provider operations without changing anything")
	migrate.Flags().BoolVar(&wait, "wait", true, "wait for the migration to finish")
	cmd.AddCommand(migrate)

	var rotDry, rotWait bool
	rotate := &cobra.Command{
		Use:   "rotate [--dry-run]",
		Short: "Rewrap every rypt wrap under the current rypt key version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := open(cmd, e, g, true)
			if err != nil {
				return err
			}
			return startMigration(cmd.Context(), s, gen.KeyMigrationRequest{Kind: gen.KeyMigrationRequestKindRotate, DryRun: &rotDry}, rotWait)
		},
	}
	rotate.Flags().BoolVar(&rotDry, "dry-run", false, "report the provider operations without changing anything")
	rotate.Flags().BoolVar(&rotWait, "wait", true, "wait for the migration to finish")
	cmd.AddCommand(rotate)

	var follow bool
	show := &cobra.Command{
		Use:   "migration ID",
		Short: "Show a migration's progress",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := open(cmd, e, g, true)
			if err != nil {
				return err
			}
			if follow {
				return waitMigration(cmd.Context(), s, args[0])
			}
			r, err := s.client.GetKeyMigrationWithResponse(cmd.Context(), args[0])
			if err := check(r, err, 200); err != nil {
				return err
			}
			return s.out(r.JSON200, func(w io.Writer) { printMigration(w, r.JSON200) })
		},
	}
	show.Flags().BoolVar(&follow, "wait", false, "wait for it to finish")
	cmd.AddCommand(show)
	return cmd
}

func printMigration(w io.Writer, m *gen.KeyMigration) {
	fmt.Fprintf(w, "Migration %s (%s): %s, %d of %d projects", m.Id, m.Kind, m.State, m.ProjectsDone, m.ProjectsTotal)
	if m.Error != nil {
		fmt.Fprintf(w, "; error: %s", *m.Error)
	}
	fmt.Fprintln(w)
}

func startMigration(ctx context.Context, s *session, body gen.KeyMigrationRequest, wait bool) error {
	r, err := s.client.StartKeyMigrationWithResponse(ctx, body)
	if err := check(r, err, 200, 202); err != nil {
		return err
	}
	if r.JSON200 != nil {
		est := r.JSON200
		return s.out(est, func(w io.Writer) {
			fmt.Fprintf(w, "Dry run: %d provider operations in total (%d for the instance keys).\n", est.TotalOps, deref(est.InstanceOps))
			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			if len(est.Projects) > 0 {
				fmt.Fprintln(tw, "TENANT\tPROJECT\tOPERATIONS")
			}
			for _, p := range est.Projects {
				fmt.Fprintf(tw, "%s\t%s\t%d\n", p.Tenant, p.Project, p.Ops)
			}
			tw.Flush()
		})
	}
	m := r.JSON202
	if !wait || s.json() {
		return s.out(m, func(w io.Writer) { printMigration(w, m) })
	}
	fmt.Fprintf(s.e.stderr, "Started migration %s.\n", m.Id)
	return waitMigration(ctx, s, m.Id)
}

func waitMigration(ctx context.Context, s *session, id string) error {
	for {
		r, err := s.client.GetKeyMigrationWithResponse(ctx, id)
		if err := check(r, err, 200); err != nil {
			return err
		}
		m := r.JSON200
		switch m.State {
		case gen.Succeeded:
			return s.out(m, func(w io.Writer) { printMigration(w, m) })
		case gen.Failed:
			_ = s.out(m, func(w io.Writer) { printMigration(w, m) })
			return &exitError{code: 1}
		}
		fmt.Fprintf(s.e.stderr, "  %d of %d projects...\n", m.ProjectsDone, m.ProjectsTotal)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
