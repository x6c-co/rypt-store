import { describe, expect, it } from "vitest";
import { parseDotenv } from "./dotenv";

describe("parseDotenv", () => {
  it("parses the common forms", () => {
    const r = parseDotenv(
      [
        "# comment",
        "",
        "PLAIN=value",
        "export EXPORTED=yes",
        "SPACED = padded  ",
        "INLINE=abc # trailing comment",
        "HASH_IN_VALUE=abc#def",
        "SINGLE='it is $literal \\n'",
        'DOUBLE="line1\\nline2\\t\\"q\\""',
        'MULTI="first',
        "second",
        'third"',
        "EMPTY=",
        'EMPTY_QUOTED=""',
      ].join("\n"),
    );
    const map = Object.fromEntries(r.entries.map((e) => [e.name, e.value]));
    expect(r.problems).toEqual([]);
    expect(map).toEqual({
      PLAIN: "value",
      EXPORTED: "yes",
      SPACED: "padded",
      INLINE: "abc",
      HASH_IN_VALUE: "abc#def",
      SINGLE: "it is $literal \\n",
      DOUBLE: 'line1\nline2\t"q"',
      MULTI: "first\nsecond\nthird",
      EMPTY: "",
      EMPTY_QUOTED: "",
    });
    expect(r.entries.find((e) => e.name === "MULTI")?.line).toBe(10);
  });

  it("reports invalid names and lines", () => {
    const r = parseDotenv(["1BAD=x", "no equals here", "GOOD=1", 'OPEN="never closed', "has-dash=1"].join("\n"));
    expect(r.entries.map((e) => e.name)).toEqual(["GOOD"]);
    expect(r.problems.map((p) => p.line)).toEqual([1, 2, 4]);
    expect(r.problems[0]?.name).toBe("1BAD");
  });

  it("lets a later assignment win, in the first position", () => {
    const r = parseDotenv("A=1\nB=2\nA=3\r\n");
    expect(r.entries).toEqual([
      { name: "A", value: "3", line: 3 },
      { name: "B", value: "2", line: 2 },
    ]);
  });

  it("rejects text after a closing quote", () => {
    const r = parseDotenv('A="x" y\nB=\'x\' # ok');
    expect(r.entries.map((e) => e.name)).toEqual(["B"]);
    expect(r.problems[0]?.line).toBe(1);
  });
});
