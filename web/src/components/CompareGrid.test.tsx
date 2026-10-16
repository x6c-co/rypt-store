import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Schemas } from "../api/client";
import { CompareGrid } from "./CompareGrid";

const env = (slug: string, position: number): Schemas["Environment"] => ({ id: `id-${slug}`, name: slug, slug, position, created_at: "2026-10-01T00:00:00Z" });

const grid: Schemas["CompareGrid"] = {
  environments: [env("dev", 0), env("staging", 1), env("prod", 2)],
  rows: [
    {
      name: "DATABASE_URL",
      cells: [
        { environment: "dev", missing: false, group: 1, secret: "DB-dev" },
        { environment: "staging", missing: false, group: 1, secret: "DB-staging" },
        { environment: "prod", missing: false, group: 2, secret: "DB-prod" },
      ],
    },
    {
      name: "STRIPE_KEY",
      cells: [
        { environment: "dev", missing: false, group: 1, secret: "STRIPE-dev" },
        { environment: "staging", missing: false, group: 2, secret: "STRIPE-staging" },
        { environment: "prod", missing: true, group: null, secret: null },
      ],
    },
  ],
};

describe("CompareGrid", () => {
  it("renders set, equal, different and missing cells without values", () => {
    const { container } = render(<CompareGrid grid={grid} canWrite onOpen={() => {}} onAdd={() => {}} />);
    const row = screen.getByRole("row", { name: /DATABASE_URL/ });
    expect(within(row).getByRole("button", { name: "DATABASE_URL in staging has the same value as in dev" })).toBeTruthy();
    expect(within(row).getByRole("button", { name: "DATABASE_URL in prod differs from every other environment" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /STRIPE_KEY is missing in prod\. Add to prod/ })).toBeTruthy();
    expect(container.textContent).toContain("=dev");
    expect(container.textContent).toContain("≠");
    expect(container.textContent).toContain("Add to prod");
  });

  it("opens a set cell and offers Add on a missing one", () => {
    const onOpen = vi.fn();
    const onAdd = vi.fn();
    render(<CompareGrid grid={grid} canWrite onOpen={onOpen} onAdd={onAdd} />);
    fireEvent.click(screen.getByRole("button", { name: "STRIPE_KEY in dev differs from every other environment" }));
    // Cells open the secret by ID, not by name.
    expect(onOpen).toHaveBeenCalledWith("dev", "STRIPE-dev");
    fireEvent.click(screen.getByRole("button", { name: /Add to prod/ }));
    expect(onAdd).toHaveBeenCalledWith("prod", "STRIPE_KEY");
  });

  it("does not offer Add without write access", () => {
    render(<CompareGrid grid={grid} canWrite={false} onOpen={() => {}} onAdd={() => {}} />);
    expect(screen.queryByRole("button", { name: /Add to/ })).toBeNull();
  });
});
