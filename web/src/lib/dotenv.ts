// A client-side preview of the server's .env parser (feature 01 3.7):
// KEY=value, an optional `export ` prefix, single and double quotes, `\n`
// escapes and multi-line values inside double quotes, and `#` comments.
// The server's parse is authoritative; this only previews an import.

export const SECRET_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,255}$/;

export interface DotenvEntry {
  name: string;
  value: string;
  line: number;
}

export interface DotenvProblem {
  line: number;
  name?: string;
  reason: string;
}

export interface DotenvResult {
  entries: DotenvEntry[];
  problems: DotenvProblem[];
}

const ESCAPES: Record<string, string> = { n: "\n", r: "\r", t: "\t", '"': '"', "\\": "\\" };

export function parseDotenv(text: string): DotenvResult {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const entries: DotenvEntry[] = [];
  const problems: DotenvProblem[] = [];
  const index = new Map<string, number>();

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    let line = lines[i] ?? "";
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;

    line = line.replace(/^\s*export\s+/, "");
    const eq = line.indexOf("=");
    if (eq < 0) {
      problems.push({ line: lineNo, reason: "Missing `=`." });
      continue;
    }
    const name = line.slice(0, eq).trim();
    let rest = line.slice(eq + 1).replace(/^[ \t]+/, "");
    let value: string;

    if (rest.startsWith('"')) {
      // Double quotes: escapes, and the value may run over several lines.
      let buf = "";
      let j = 1;
      let closed = false;
      for (;;) {
        while (j < rest.length) {
          const ch = rest[j]!;
          if (ch === "\\" && j + 1 < rest.length) {
            const next = rest[j + 1]!;
            buf += ESCAPES[next] ?? "\\" + next;
            j += 2;
            continue;
          }
          if (ch === '"') {
            closed = true;
            break;
          }
          buf += ch;
          j++;
        }
        if (closed || i + 1 >= lines.length) break;
        buf += "\n";
        i++;
        rest = lines[i] ?? "";
        j = 0;
      }
      if (!closed) {
        problems.push({ line: lineNo, name, reason: "Unterminated double quote." });
        continue;
      }
      const tail = rest.slice(j + 1).trim();
      if (tail !== "" && !tail.startsWith("#")) {
        problems.push({ line: lineNo, name, reason: "Unexpected text after the closing quote." });
        continue;
      }
      value = buf;
    } else if (rest.startsWith("'")) {
      const end = rest.indexOf("'", 1);
      if (end < 0) {
        problems.push({ line: lineNo, name, reason: "Unterminated single quote." });
        continue;
      }
      const tail = rest.slice(end + 1).trim();
      if (tail !== "" && !tail.startsWith("#")) {
        problems.push({ line: lineNo, name, reason: "Unexpected text after the closing quote." });
        continue;
      }
      value = rest.slice(1, end);
    } else {
      // Unquoted: an inline comment starts at whitespace followed by #.
      const hash = rest.search(/\s#/);
      value = (hash >= 0 ? rest.slice(0, hash) : rest).trim();
    }

    if (!SECRET_NAME.test(name)) {
      problems.push({ line: lineNo, name, reason: "Names start with a letter or underscore and contain only letters, digits and underscores." });
      continue;
    }
    // A later assignment of the same name wins, as in most dotenv loaders.
    const prior = index.get(name);
    if (prior !== undefined) {
      entries[prior] = { name, value, line: lineNo };
    } else {
      index.set(name, entries.length);
      entries.push({ name, value, line: lineNo });
    }
  }
  return { entries, problems };
}
