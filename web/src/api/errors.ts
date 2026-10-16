// API errors are RFC 9457 problem documents with a stable `code` (core 9).

export interface FieldError {
  field: string;
  message: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail?: string;
  readonly requestId?: string;
  readonly fieldErrors: FieldError[];

  constructor(status: number, code: string, message: string, opts: { detail?: string; requestId?: string; fieldErrors?: FieldError[] } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.detail = opts.detail;
    this.requestId = opts.requestId;
    this.fieldErrors = opts.fieldErrors ?? [];
  }

  /** Builds an ApiError from a failed response and its decoded body. */
  static from(response: Pick<Response, "status" | "statusText" | "headers">, body: unknown): ApiError {
    const p = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
    const code = typeof p.code === "string" && p.code ? p.code : fallbackCode(response.status);
    const detail = typeof p.detail === "string" ? p.detail : undefined;
    const title = typeof p.title === "string" ? p.title : response.statusText || "Request failed";
    const requestId = (typeof p.request_id === "string" ? p.request_id : undefined) ?? response.headers.get("X-Request-Id") ?? undefined;
    const fieldErrors = Array.isArray(p.errors)
      ? (p.errors as unknown[]).flatMap((e) => {
          const fe = e as Record<string, unknown>;
          return typeof fe.field === "string" && typeof fe.message === "string" ? [{ field: fe.field, message: fe.message }] : [];
        })
      : [];
    return new ApiError(response.status, code, detail ?? title, { detail, requestId, fieldErrors });
  }

  /** The message for one form field, if the server named it. */
  fieldError(field: string): string | undefined {
    return this.fieldErrors.find((e) => e.field === field)?.message;
  }
}

function fallbackCode(status: number): string {
  switch (status) {
    case 400:
      return "validation_failed";
    case 401:
      return "unauthorized";
    case 403:
      return "forbidden";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    case 429:
      return "rate_limited";
    case 503:
      return "key_provider_unavailable";
    default:
      return "internal";
  }
}

/** Where the app must go when a request fails for this reason. */
export type AuthRedirect = "login" | "mfa" | "enroll" | "setup";

export function authRedirectFor(err: unknown): AuthRedirect | null {
  if (!(err instanceof ApiError)) return null;
  switch (err.code) {
    case "unauthorized":
      return "login";
    case "mfa_required":
      return "mfa";
    case "mfa_enrollment_required":
      return "enroll";
    case "setup_required":
      return "setup";
  }
  return null;
}

/** A plain-language message for any error. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.code) {
      case "invalid_credentials":
        return "That email and password do not match.";
      case "rate_limited":
        return "Too many attempts. Wait a few minutes and try again.";
      case "key_provider_unavailable":
        return "The key provider is unreachable, so values cannot be read or written right now.";
      case "key_provider_quota":
        return "The rypt.dev operation quota is used up, so values cannot be read or written until it resets.";
      case "csrf_header_required":
        return "The request was refused. Reload the page and try again.";
      case "conflict":
        return err.detail ?? "Someone else changed this first.";
      case "not_found":
        return err.detail ?? "Not found.";
      case "forbidden":
        return err.detail ?? "You do not have permission to do that.";
    }
    if (err.fieldErrors.length > 0 && !err.detail) {
      return err.fieldErrors.map((e) => `${e.field}: ${e.message}`).join("; ");
    }
    return err.message;
  }
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}
