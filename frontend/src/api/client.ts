// Typed fetch client for /api/v1, built on the types generated from the
// server's OpenAPI schema (src/api/schema.d.ts, `npm run gen:api`). A path
// or a response field the server does not have is a compile error here.
//
// Two rules of the API are applied in one place rather than by every caller:
//   * every mutating request carries X-CSRF-Token (the session's token);
//   * a write against a resource sends If-Match with the ETag its read
//     returned, and a 412 surfaces as a ConflictError the UI can offer a
//     reload for.
import type { components, paths } from "./schema";

export const API_BASE = "/api/v1";

export type Schemas = components["schemas"];

type GetPath = {
  [P in keyof paths]: paths[P] extends { get: object } ? P : never;
}[keyof paths];

type GetOp<P extends GetPath> = paths[P] extends { get: infer O } ? O : never;

type Json<R> = R extends { content: { "application/json": infer T } } ? T : never;

export type GetResponse<P extends GetPath> = GetOp<P> extends { responses: { 200: infer R } }
  ? Json<R>
  : never;

type Query<P extends GetPath> = GetOp<P> extends { parameters: { query?: infer Q } }
  ? Q
  : never;

type PathParams<P extends GetPath> = GetOp<P> extends { parameters: { path: infer Q } }
  ? Q
  : never;

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** The resource changed since it was read (HTTP 412). */
export class ConflictError extends ApiError {
  constructor(message: string) {
    super(412, message);
    this.name = "ConflictError";
  }
}

let csrfToken = "";

/** Set from the session response; sent on every mutating request. */
export function setCsrfToken(token: string): void {
  csrfToken = token;
}

/** ETag of the last successful read, per URL -- what a write sends back. */
const etags = new Map<string, string>();

export function etagFor(path: string): string | undefined {
  return etags.get(path);
}

function expand(path: string, params?: Record<string, unknown>): string {
  return path.replace(/\{(\w+)\}/g, (_m, key: string) =>
    encodeURIComponent(String(params?.[key] ?? "")),
  );
}

function withQuery(path: string, query?: Record<string, unknown>): string {
  if (!query) return path;
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `${path}?${text}` : path;
}

async function failure(response: Response): Promise<ApiError> {
  let message = response.statusText || `HTTP ${response.status}`;
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "error" in body) {
      message = String((body as { error: unknown }).error);
    }
  } catch {
    // Not JSON -- keep the status text.
  }
  if (response.status === 412) return new ConflictError(message);
  return new ApiError(response.status, message);
}

export async function apiGet<P extends GetPath>(
  path: P,
  options: { query?: Query<P>; path?: PathParams<P>; signal?: AbortSignal } = {},
): Promise<GetResponse<P>> {
  const url = withQuery(
    expand(path, options.path as Record<string, unknown> | undefined),
    options.query as Record<string, unknown> | undefined,
  );
  const response = await fetch(`${API_BASE}${url}`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    signal: options.signal,
  });
  if (!response.ok) throw await failure(response);
  const etag = response.headers.get("ETag");
  if (etag) etags.set(url, etag);
  return (await response.json()) as GetResponse<P>;
}

export interface SendOptions {
  body?: unknown;
  /** The URL whose last-read ETag this write is based on. */
  ifMatchOf?: string;
  /** An explicit ETag, when the caller holds one. */
  ifMatch?: string;
}

/** A mutating request: CSRF header always, If-Match when it edits a resource. */
export async function apiSend<T = unknown>(
  method: "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  options: SendOptions = {},
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-CSRF-Token": csrfToken,
  };
  const ifMatch = options.ifMatch ?? (options.ifMatchOf ? etags.get(options.ifMatchOf) : undefined);
  if (ifMatch) headers["If-Match"] = ifMatch;
  let body: string | undefined;
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    credentials: "same-origin",
    headers,
    body,
  });
  if (!response.ok) throw await failure(response);
  // The write's own ETag is the next write's If-Match: two edits in a row
  // on one page must not need a reload in between.
  const etag = response.headers.get("ETag");
  if (etag && options.ifMatchOf) etags.set(options.ifMatchOf, etag);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function resetClientState(): void {
  csrfToken = "";
  etags.clear();
}
