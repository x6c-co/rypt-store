// Cell labels for the Compare grid (core 14.3, feature 01 3.6). The server
// sends per row, per environment, `missing` or a group number; cells with
// the same group in a row have equal values. Groups carry no meaning
// outside their row.

export interface CompareCellIn {
  environment: string;
  missing: boolean;
  /** The secret's ID in this environment; null when missing. */
  secret?: string | null;
  group?: number | null;
}

export type CellKind = "missing" | "set" | "same" | "different";

export interface CellView {
  environment: string;
  kind: CellKind;
  /** Short visible text: "—", "●", "● =dev", "● ≠". */
  text: string;
  /** Full description for screen readers and tooltips. */
  label: string;
  /** For "same": the environment whose value this cell repeats. */
  sameAs?: string;
  /** The secret's ID in this environment, for opening it. */
  secret: string | null;
}

/**
 * Describes each cell of one row:
 * - missing: the secret is not in that environment.
 * - same: equal to the value in an earlier (left) environment, named.
 * - different: set, and no other environment in the row has this value,
 *   while at least one other environment has the secret.
 * - set: the first of several equal cells, or the only environment that has it.
 */
export function describeRow(name: string, cells: CompareCellIn[]): CellView[] {
  const setCells = cells.filter((c) => !c.missing);
  const groupCount = new Map<number, number>();
  for (const c of setCells) {
    const g = c.group ?? -1;
    groupCount.set(g, (groupCount.get(g) ?? 0) + 1);
  }
  const firstOfGroup = new Map<number, string>();

  return cells.map((c) => {
    if (c.missing) {
      return { environment: c.environment, kind: "missing", text: "—", label: `${name} is missing in ${c.environment}`, secret: null };
    }
    const g = c.group ?? -1;
    const first = firstOfGroup.get(g);
    if (first !== undefined) {
      return {
        environment: c.environment,
        kind: "same",
        text: `● =${first}`,
        label: `${name} in ${c.environment} has the same value as in ${first}`,
        sameAs: first,
        secret: c.secret ?? null,
      };
    }
    firstOfGroup.set(g, c.environment);
    if (setCells.length > 1 && (groupCount.get(g) ?? 0) === 1) {
      return {
        environment: c.environment,
        kind: "different",
        text: "● ≠",
        label: `${name} in ${c.environment} differs from every other environment`,
        secret: c.secret ?? null,
      };
    }
    return { environment: c.environment, kind: "set", text: "●", label: `${name} is set in ${c.environment}`, secret: c.secret ?? null };
  });
}
