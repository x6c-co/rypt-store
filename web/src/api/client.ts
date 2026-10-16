import createClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./schema";
import { ApiError } from "./errors";

export type Schemas = components["schemas"];

/** The header that marks state-changing SPA requests (core 7.3, CSRF). */
export const CSRF_HEADER = "X-Rypt-Store-Request";

export const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      request.headers.set(CSRF_HEADER, "1");
    }
    return request;
  },
};

function origin(): string {
  return typeof window !== "undefined" && window.location ? window.location.origin : "http://localhost";
}

export const api = createClient<paths>({ baseUrl: origin(), credentials: "same-origin" });
api.use(csrfMiddleware);

interface Result<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/** Awaits an openapi-fetch call and returns its data or throws ApiError. */
export async function call<T>(p: Promise<Result<T>>): Promise<T> {
  const { data, error, response } = await p;
  if (!response.ok) throw ApiError.from(response, error);
  return data as T;
}

/** Like call, but also returns the response, for headers such as ETag. */
export async function callWithResponse<T>(p: Promise<Result<T>>): Promise<{ data: T; response: Response }> {
  const { data, error, response } = await p;
  if (!response.ok) throw ApiError.from(response, error);
  return { data: data as T, response };
}

/** Raw fetch for endpoints whose bodies are not JSON (exports, imports). */
export async function rawFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") headers.set(CSRF_HEADER, "1");
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    throw ApiError.from(response, body);
  }
  return response;
}

/** The current version from an ETag such as `"3"`. */
export function versionFromETag(etag: string | null | undefined): number | null {
  if (!etag) return null;
  const m = /^(?:W\/)?"?(\d+)"?$/.exec(etag.trim());
  return m?.[1] ? Number(m[1]) : null;
}

/** The If-Match value for a version. */
export function etagFor(version: number): string {
  return `"${version}"`;
}

/** Path prefix helpers. */
export const enc = encodeURIComponent;
export function projectPath(tenant: string, project: string): string {
  return `/api/v1/tenants/${enc(tenant)}/projects/${enc(project)}`;
}
export function envPath(tenant: string, project: string, env: string): string {
  return `${projectPath(tenant, project)}/environments/${enc(env)}`;
}
