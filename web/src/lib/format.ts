const dateTime = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

const dateOnly = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" });

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : dateTime.format(d);
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : dateOnly.format(d);
}

export function relativeTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.round((now - t) / 1000);
  const abs = Math.abs(s);
  const fmt = (n: number, unit: string) => `${n} ${unit}${n === 1 ? "" : "s"}`;
  const out =
    abs < 45 ? "moments" : abs < 3600 ? fmt(Math.round(abs / 60), "minute") : abs < 86400 ? fmt(Math.round(abs / 3600), "hour") : fmt(Math.round(abs / 86400), "day");
  if (out === "moments") return s >= 0 ? "just now" : "in moments";
  return s >= 0 ? `${out} ago` : `in ${out}`;
}

/** Shortens a hash for display, keeping both ends. */
export function shortHash(h: string, n = 10): string {
  return h.length <= 2 * n + 1 ? h : `${h.slice(0, n)}…${h.slice(-n)}`;
}

/** A slug suggestion from a name, matching the API's slug pattern. */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64)
    .replace(/-+$/g, "");
}

/** A local datetime-local input value to an RFC 3339 string. */
export function localInputToISO(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export function isoToDateInput(iso: string): string {
  return iso.slice(0, 10);
}
