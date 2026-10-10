import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetClientState } from "@/api/client";
import { App } from "@/App";
import { AuthProvider } from "@/auth";

type Handler = (url: string, init: RequestInit) => Response | undefined;

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

const SESSION = {
  identity: "eye", role: "viewer", can_write: false, read_only: false, csrf: "c", version: "0.52.0",
};

function serve(handler: Handler) {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const response = handler(String(input), init);
    if (!response) throw new Error(`unexpected request ${init.method ?? "GET"} ${String(input)}`);
    return response;
  }));
}

function renderAt(path: string): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrap = (children: ReactNode) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider>{children}</AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  render(wrap(<App />));
}

beforeEach(() => resetClientState());
afterEach(() => vi.unstubAllGlobals());

describe("sign-in", () => {
  it("redirects to the login page without a session, and shows the server's refusal", async () => {
    serve((url, init) => {
      if (url.endsWith("/session") && !init.method) return json(401, { error: "Not signed in." });
      if (url.endsWith("/session") && init.method === "POST") return json(401, { error: "Sign-in failed." });
      return undefined;
    });
    renderAt("/credentials");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Identity"), "eye");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Sign-in failed.");
    // The password field is cleared after a failure.
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("posts the credentials as JSON and lands on the overview", async () => {
    let posted: unknown;
    serve((url, init) => {
      if (url.endsWith("/session") && !init.method) return json(401, { error: "Not signed in." });
      if (url.endsWith("/session") && init.method === "POST") {
        posted = JSON.parse(String(init.body));
        return json(200, SESSION);
      }
      if (url.endsWith("/overview")) return json(500, { error: "boom" });
      return undefined;
    });
    renderAt("/login");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Identity"), "eye");
    await user.type(screen.getByLabelText("Password"), "viewer-console-password");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(posted).toEqual({ identity: "eye", password: "viewer-console-password" }));
    expect(await screen.findByText("Could not load this page.")).toBeInTheDocument();
  });
});

describe("credentials page", () => {
  it("shows metadata only and flags dangling references", async () => {
    serve((url) => {
      if (url.endsWith("/session")) return json(200, SESSION);
      if (url.endsWith("/credentials")) {
        return json(200, {
          configured: true,
          dangling: ["ghost-key"],
          credentials: [{
            name: "demo-key", kind: "bearer", header: null, created_at: "2026-10-10T10:00:00+0000",
            rotated_at: null, in_overlap: false, used_by: ["demo"], probe_url: null,
            probe_status: "no_probe_url", probe_checked_at: null, suspect_status: null, suspect_at: null,
          }],
        });
      }
      return undefined;
    });
    renderAt("/credentials");
    expect(await screen.findByText("demo-key")).toBeInTheDocument();
    expect(screen.getByText("ghost-key")).toBeInTheDocument();
    // Write-only store: nothing on the page offers to reveal a value.
    expect(screen.queryByText(/show value|reveal/i)).toBeNull();
    expect(screen.queryByRole("textbox", { name: /value/i })).toBeNull();
  });
});

describe("role display", () => {
  it("marks a read-only deployment in the sidebar", async () => {
    serve((url) => {
      if (url.endsWith("/session")) return json(200, { ...SESSION, role: "admin", read_only: true });
      if (url.endsWith("/account")) return json(200, { identity: "eye", role: "admin", can_change_password: false });
      return undefined;
    });
    renderAt("/account");
    expect(await screen.findByText("read-only")).toBeInTheDocument();
    expect(await screen.findByText(/deployment is read-only/)).toBeInTheDocument();
  });
});
