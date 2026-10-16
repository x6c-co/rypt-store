import type { Schemas } from "../api/client";
import { describeRow } from "../lib/compare";

/**
 * The Compare grid (core 14.3): rows are secret names, columns are
 * environments. Each cell shows set, missing, or equal to another
 * environment, from server-side value MACs; no values reach the browser.
 */
export function CompareGrid({
  grid,
  canWrite,
  onOpen,
  onAdd,
}: {
  grid: Schemas["CompareGrid"];
  canWrite: boolean;
  /** Opens the secret with this ID in that environment. */
  onOpen(environment: string, secret: string): void;
  onAdd(environment: string, name: string): void;
}) {
  const envName = (slug: string) => grid.environments.find((e) => e.slug === slug)?.name ?? slug;
  return (
    <div className="table-wrap">
      <table className="table compare">
        <caption className="visually-hidden">Secrets compared across environments</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            {grid.environments.map((e) => (
              <th scope="col" key={e.id}>
                {e.name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {grid.rows.map((row) => {
            const cells = describeRow(row.name, row.cells);
            return (
              <tr key={row.name}>
                <th scope="row" className="mono">
                  {row.name}
                </th>
                {cells.map((c) => (
                  <td key={c.environment} className={`cell cell-${c.kind}`}>
                    {c.kind === "missing" ? (
                      canWrite ? (
                        <button type="button" className="cell-btn" onClick={() => onAdd(c.environment, row.name)} aria-label={`${c.label}. Add to ${envName(c.environment)}`}>
                          <span aria-hidden="true">—</span>
                          <span className="add">Add to {envName(c.environment)}</span>
                        </button>
                      ) : (
                        <span className="cell-btn cell-static" aria-label={c.label}>
                          <span aria-hidden="true">—</span>
                        </span>
                      )
                    ) : (
                      <button type="button" className="cell-btn" onClick={() => c.secret && onOpen(c.environment, c.secret)} title={c.label} aria-label={c.label}>
                        <span className="dot" aria-hidden="true">
                          ●
                        </span>
                        {c.kind === "same" && (
                          <span className="rel" aria-hidden="true">
                            ={c.sameAs}
                          </span>
                        )}
                        {c.kind === "different" && (
                          <span className="rel" aria-hidden="true">
                            ≠
                          </span>
                        )}
                      </button>
                    )}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function CompareLegend() {
  return (
    <div className="legend" aria-label="Legend">
      <span>
        <span className="mono">●</span> set
      </span>
      <span>
        <span className="mono">● =dev</span> same value as dev
      </span>
      <span>
        <span className="mono">● ≠</span> differs from every other environment
      </span>
      <span>
        <span className="mono">—</span> missing
      </span>
    </div>
  );
}
