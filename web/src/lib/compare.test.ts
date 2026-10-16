import { describe, expect, it } from "vitest";
import { describeRow } from "./compare";

const cell = (environment: string, group: number | null) => ({
  environment,
  missing: group === null,
  group,
  secret: group === null ? null : `id-${environment}`,
});

describe("describeRow", () => {
  it("marks equal, different, and missing cells", () => {
    const v = describeRow("LOG_LEVEL", [cell("dev", 1), cell("staging", 1), cell("prod", 2)]);
    expect(v.map((c) => c.kind)).toEqual(["set", "same", "different"]);
    expect(v[1]?.text).toBe("● =dev");
    expect(v[1]?.sameAs).toBe("dev");
    expect(v[2]?.text).toBe("● ≠");
    expect(v.map((c) => c.secret)).toEqual(["id-dev", "id-staging", "id-prod"]);
  });

  it("treats a lone set cell as plain set", () => {
    const v = describeRow("STRIPE_KEY", [cell("dev", 1), cell("staging", null), cell("prod", null)]);
    expect(v.map((c) => c.text)).toEqual(["●", "—", "—"]);
    expect(v[1]?.label).toBe("STRIPE_KEY is missing in staging");
    expect(v[1]?.secret).toBeNull();
  });

  it("marks every cell different when all values differ", () => {
    const v = describeRow("DATABASE_URL", [cell("dev", 1), cell("staging", 2), cell("prod", 3)]);
    expect(v.map((c) => c.kind)).toEqual(["different", "different", "different"]);
  });

  it("names the leftmost environment for repeated groups", () => {
    const v = describeRow("X", [cell("dev", 2), cell("qa", 1), cell("staging", 2), cell("prod", 1)]);
    expect(v.map((c) => c.text)).toEqual(["●", "●", "● =dev", "● =qa"]);
  });
});
