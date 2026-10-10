import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError, ConflictError, apiGet, apiSend, etagFor, resetClientState, setCsrfToken,
} from "@/api/client";

function respond(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  resetClientState();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

function lastCall(): { url: string; init: RequestInit; headers: Record<string, string> } {
  const [url, init = {}] = fetchMock.mock.calls.at(-1) ?? [];
  return { url: String(url), init, headers: (init.headers ?? {}) as Record<string, string> };
}

describe("apiGet", () => {
  it("builds the URL from typed path and query params, skipping empty ones", async () => {
    fetchMock.mockResolvedValue(respond(200, { entries: [], next_cursor: null, window_truncated: false }));
    await apiGet("/audit", { query: { identity: "bot", tool: "", outcome: "denied", limit: 10 } });
    expect(lastCall().url).toBe("/api/v1/audit?identity=bot&outcome=denied&limit=10");
    expect(lastCall().init.credentials).toBe("same-origin");
  });

  it("encodes path parameters", async () => {
    fetchMock.mockResolvedValue(respond(200, {}));
    await apiGet("/tools/{tool_id}", { path: { tool_id: "a.b@nas 1" } });
    expect(lastCall().url).toBe("/api/v1/tools/a.b%40nas%201");
  });

  it("remembers the ETag of each read", async () => {
    fetchMock.mockResolvedValue(respond(200, { tools: [] }, { ETag: '"rev-1"' }));
    await apiGet("/tools");
    expect(etagFor("/tools")).toBe('"rev-1"');
  });

  it("surfaces the server's error sentence", async () => {
    fetchMock.mockResolvedValue(respond(401, { error: "Not signed in." }));
    const error = await apiGet("/session").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(401);
    expect((error as ApiError).message).toBe("Not signed in.");
  });
});

describe("apiSend", () => {
  it("always sends the CSRF token", async () => {
    setCsrfToken("tok-123");
    fetchMock.mockResolvedValue(respond(204, null));
    await apiSend("DELETE", "/session");
    expect(lastCall().init.method).toBe("DELETE");
    expect(lastCall().headers["X-CSRF-Token"]).toBe("tok-123");
    expect(lastCall().headers["If-Match"]).toBeUndefined();
  });

  it("sends If-Match from the ETag of the resource it edits", async () => {
    setCsrfToken("tok");
    fetchMock.mockResolvedValueOnce(respond(200, { tools: [] }, { ETag: '"rev-7"' }));
    await apiGet("/tools");
    fetchMock.mockResolvedValueOnce(respond(200, { ok: true }));
    await apiSend("POST", "/tools", { body: { yaml: "id: x" }, ifMatchOf: "/tools" });
    expect(lastCall().headers["If-Match"]).toBe('"rev-7"');
    expect(lastCall().headers["Content-Type"]).toBe("application/json");
    expect(lastCall().init.body).toBe(JSON.stringify({ yaml: "id: x" }));
  });

  it("turns a 412 into a ConflictError", async () => {
    fetchMock.mockResolvedValue(respond(412, { error: "The resource changed since you loaded it." }));
    const error = await apiSend("POST", "/tools", { ifMatch: '"old"' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConflictError);
    expect((error as ConflictError).status).toBe(412);
  });
});
