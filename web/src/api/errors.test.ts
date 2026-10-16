import { describe, expect, it } from "vitest";
import { csrfMiddleware, CSRF_HEADER, etagFor, versionFromETag } from "./client";
import { ApiError, authRedirectFor, errorMessage } from "./errors";

const res = (status: number, headers: Record<string, string> = {}) => ({ status, statusText: "", headers: new Headers(headers) });

describe("ApiError.from", () => {
  it("reads a problem document", () => {
    const e = ApiError.from(res(400, { "X-Request-Id": "hdr" }), {
      type: "about:blank",
      title: "Bad request",
      status: 400,
      code: "validation_failed",
      detail: "name is invalid",
      request_id: "req-1",
      errors: [{ field: "name", message: "must match the pattern" }, { bogus: true }],
    });
    expect(e.code).toBe("validation_failed");
    expect(e.status).toBe(400);
    expect(e.message).toBe("name is invalid");
    expect(e.requestId).toBe("req-1");
    expect(e.fieldError("name")).toBe("must match the pattern");
    expect(e.fieldErrors).toHaveLength(1);
  });

  it("falls back to a code from the status", () => {
    expect(ApiError.from(res(401), null).code).toBe("unauthorized");
    expect(ApiError.from(res(409), "not json").code).toBe("conflict");
    expect(ApiError.from(res(500, { "X-Request-Id": "r9" }), {}).requestId).toBe("r9");
  });
});

describe("authRedirectFor", () => {
  it("maps auth codes to screens", () => {
    const mk = (code: string, status = 403) => new ApiError(status, code, code);
    expect(authRedirectFor(mk("unauthorized", 401))).toBe("login");
    expect(authRedirectFor(mk("mfa_required"))).toBe("mfa");
    expect(authRedirectFor(mk("mfa_enrollment_required"))).toBe("enroll");
    expect(authRedirectFor(mk("setup_required"))).toBe("setup");
    expect(authRedirectFor(mk("forbidden"))).toBeNull();
    expect(authRedirectFor(new Error("x"))).toBeNull();
  });
});

describe("errorMessage", () => {
  it("names the rypt.dev quota", () => {
    expect(errorMessage(new ApiError(503, "key_provider_quota", "x"))).toMatch(/rypt\.dev operation quota/);
    expect(errorMessage(new ApiError(503, "key_provider_unavailable", "x"))).toMatch(/unreachable/);
    expect(errorMessage(new ApiError(401, "invalid_credentials", "x"))).toMatch(/do not match/);
    expect(errorMessage("weird")).toBe("Something went wrong.");
  });
});

describe("client helpers", () => {
  it("parses ETags", () => {
    expect(versionFromETag('"3"')).toBe(3);
    expect(versionFromETag('W/"12"')).toBe(12);
    expect(versionFromETag("7")).toBe(7);
    expect(versionFromETag(null)).toBeNull();
    expect(versionFromETag('"abc"')).toBeNull();
    expect(etagFor(4)).toBe('"4"');
  });

  it("marks state-changing requests with the CSRF header", async () => {
    const run = async (method: string) => {
      const request = new Request("http://localhost/api/v1/x", { method });
      const out = await csrfMiddleware.onRequest!({ request } as Parameters<NonNullable<typeof csrfMiddleware.onRequest>>[0]);
      return (out as Request).headers.get(CSRF_HEADER);
    };
    expect(await run("POST")).toBe("1");
    expect(await run("PUT")).toBe("1");
    expect(await run("DELETE")).toBe("1");
    expect(await run("GET")).toBeNull();
  });
});
