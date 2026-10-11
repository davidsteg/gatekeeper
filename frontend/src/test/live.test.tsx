import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetClientState } from "@/api/client";
import { App } from "@/App";
import { AuthProvider } from "@/auth";

// A stand-in for the browser's EventSource that the test drives by hand.
class FakeEventSource {
  static last: FakeEventSource | undefined;
  static readonly CLOSED = 2;
  readonly url: string;
  readyState = 0;
  onerror: (() => void) | null = null;
  closed = false;
  private listeners = new Map<string, ((e: MessageEvent<string>) => void)[]>();
  constructor(url: string) {
    this.url = url;
    FakeEventSource.last = this;
  }
  addEventListener(name: string, fn: (e: MessageEvent<string>) => void) {
    this.listeners.set(name, [...(this.listeners.get(name) ?? []), fn]);
  }
  emit(name: string, data: unknown = {}) {
    for (const fn of this.listeners.get(name) ?? []) fn(new MessageEvent(name, { data: JSON.stringify(data) }));
  }
  close() {
    this.closed = true;
  }
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

const ADMIN = {
  identity: "root", role: "admin", can_write: true, read_only: false, csrf: "tok", version: "1.2.0",
};

const PENDING = {
  id: "p1", action: "tool_enable", actor: "hermes", payload: {}, base_rev: "r", status: "pending",
  created_at: "2026-10-10T10:00:00+0000", decided_by: null, decided_at: null, reason: null,
  review: { headline: "enable tool demo.restart", unchanged: 0, stale: null, tools: [] },
};

function renderAt(path: string): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider><App /></AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  resetClientState();
  FakeEventSource.last = undefined;
  vi.stubGlobal("EventSource", FakeEventSource);
});
afterEach(() => vi.unstubAllGlobals());

describe("live updates", () => {
  it("shows a new request without a reload when the server says requests changed", async () => {
    let proposals: unknown[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/requests/pending?status=pending")) return json(200, proposals);
      if (url.endsWith("/requests/toolkits")) return json(200, []);
      if (url.includes("/requests/decided")) return json(200, { entries: [], next_cursor: null, total: 0 });
      throw new Error(`unexpected request ${url}`);
    }));
    renderAt("/requests");
    expect(await screen.findByText(/No proposals yet/)).toBeInTheDocument();
    const source = FakeEventSource.last;
    expect(source?.url).toBe("/api/v1/events");
    act(() => source?.emit("ready"));
    expect(await screen.findByText("Live")).toBeInTheDocument();

    proposals = [PENDING];
    // A topic the page does not show refetches nothing visible.
    act(() => source?.emit("change", { topics: ["credentials"] }));
    expect(screen.queryByText("enable tool demo.restart")).toBeNull();
    act(() => source?.emit("change", { topics: ["requests"] }));
    expect(await screen.findByText("enable tool demo.restart")).toBeInTheDocument();
    // The sidebar count follows too.
    await waitFor(() => expect(screen.getByLabelText("1 open")).toBeInTheDocument());
  });

  it("falls back to polling and re-checks the session when the stream is refused", async () => {
    let sessionReads = 0;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/session")) {
        sessionReads += 1;
        return sessionReads === 1 ? json(200, ADMIN) : json(401, { error: "Not signed in." });
      }
      if (url.endsWith("/account")) return json(200, { identity: "root", role: "admin", can_change_password: true });
      if (url.includes("/requests/")) return json(200, []);
      throw new Error(`unexpected request ${url}`);
    }));
    renderAt("/account");
    expect(await screen.findByRole("heading", { name: "Account" })).toBeInTheDocument();
    const source = FakeEventSource.last;
    act(() => {
      if (!source) return;
      source.readyState = FakeEventSource.CLOSED;
      source.onerror?.();
    });
    expect(await screen.findByText("Sign in")).toBeInTheDocument();
  });

  it("keeps the revision an identity form was opened on, however often the list is reread", async () => {
    let etag = '"i1"';
    let sent: Record<string, string> | undefined;
    const ident = {
      id: "bot", role: "agent", tools: [], scopes: [], console: "api_only", unknown_tools: [],
    };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const url = String(input);
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/identities") && !init.method) return json(200, [ident], { ETag: etag });
      if (url.endsWith("/identities/bot") && init.method === "PUT") {
        sent = init.headers as Record<string, string>;
        return json(412, { error: "The resource changed since you loaded it." });
      }
      if (url.endsWith("/tools")) return json(200, { tools: [], rejected: [], disabled_by_tier1: [], toolkits: [] });
      if (url.includes("/requests/")) return json(200, []);
      throw new Error(`unexpected request ${init.method ?? "GET"} ${url}`);
    }));
    renderAt("/identities");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit" }));
    // Someone else changes identities.yaml; the live update rereads the list.
    etag = '"i2"';
    act(() => FakeEventSource.last?.emit("ready"));
    act(() => FakeEventSource.last?.emit("change", { topics: ["identities"] }));
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.filter(([u]) => String(u).endsWith("/identities")).length).toBeGreaterThan(1));
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Changed elsewhere.")).toBeInTheDocument();
    expect(sent?.["If-Match"]).toBe('"i1"');
  });
});
