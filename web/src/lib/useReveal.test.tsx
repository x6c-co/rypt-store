import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { REVEAL_MS, useReveal } from "./useReveal";

describe("useReveal", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("re-masks a value after 30 seconds", () => {
    const { result } = renderHook(() => useReveal());
    expect(REVEAL_MS).toBe(30_000);
    act(() => result.current.reveal("DB_URL", "postgres://x"));
    expect(result.current.revealed).toEqual({ DB_URL: "postgres://x" });
    act(() => vi.advanceTimersByTime(29_999));
    expect(result.current.revealed.DB_URL).toBe("postgres://x");
    act(() => vi.advanceTimersByTime(1));
    expect(result.current.revealed).toEqual({});
  });

  it("restarts the timer when revealed again and hides on demand", () => {
    const { result } = renderHook(() => useReveal(1000));
    act(() => result.current.reveal("A", "1"));
    act(() => vi.advanceTimersByTime(800));
    act(() => result.current.reveal("A", "1"));
    act(() => result.current.reveal("B", "2"));
    act(() => vi.advanceTimersByTime(800));
    expect(Object.keys(result.current.revealed).sort()).toEqual(["A", "B"]);
    act(() => result.current.hide("B"));
    expect(Object.keys(result.current.revealed)).toEqual(["A"]);
    act(() => result.current.hideAll());
    expect(result.current.revealed).toEqual({});
  });

  it("clears timers on unmount", () => {
    const { result, unmount } = renderHook(() => useReveal());
    act(() => result.current.reveal("A", "1"));
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
