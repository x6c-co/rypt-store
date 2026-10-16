import { useCallback, useEffect, useRef, useState } from "react";

/** A revealed value re-masks after this long (core 14.3). */
export const REVEAL_MS = 30_000;

/**
 * Tracks revealed secret values by key and hides each one REVEAL_MS after it
 * was revealed. Values are dropped on unmount.
 */
export function useReveal(timeoutMs: number = REVEAL_MS) {
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  const hide = useCallback((key: string) => {
    const t = timers.current.get(key);
    if (t) clearTimeout(t);
    timers.current.delete(key);
    setRevealed((r) => {
      if (!(key in r)) return r;
      const next = { ...r };
      delete next[key];
      return next;
    });
  }, []);

  const reveal = useCallback(
    (key: string, value: string) => {
      const prior = timers.current.get(key);
      if (prior) clearTimeout(prior);
      timers.current.set(
        key,
        setTimeout(() => hide(key), timeoutMs),
      );
      setRevealed((r) => ({ ...r, [key]: value }));
    },
    [hide, timeoutMs],
  );

  const hideAll = useCallback(() => {
    for (const t of timers.current.values()) clearTimeout(t);
    timers.current.clear();
    setRevealed({});
  }, []);

  useEffect(() => {
    const map = timers.current;
    return () => {
      for (const t of map.values()) clearTimeout(t);
      map.clear();
    };
  }, []);

  return { revealed, reveal, hide, hideAll };
}
