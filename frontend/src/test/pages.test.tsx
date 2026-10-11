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

  it("returns to the page it was opened at, query included, after sign-in", async () => {
    serve((url, init) => {
      if (url.endsWith("/session") && !init.method) return json(401, { error: "Not signed in." });
      if (url.endsWith("/session") && init.method === "POST") return json(200, SESSION);
      if (url.endsWith("/requests/pending?status=pending")) return json(200, []);
      if (url.includes("/requests/decided")) return json(200, { entries: [], next_cursor: null, total: 0 });
      if (url.endsWith("/requests/toolkits")) return json(200, []);
      return json(200, {});
    });
    renderAt("/requests?tab=toolkit");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Identity"), "eye");
    await user.type(screen.getByLabelText("Password"), "viewer-console-password");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("tab", { name: "Toolkit", selected: true })).toBeInTheDocument();
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

const ADMIN = { ...SESSION, identity: "root", role: "admin", can_write: true, csrf: "tok" };

const TOOL = {
  id: "demo.show", toolkit: "demo", destination: null, version: 1, title: "Show", description: "d",
  category: "read", idempotent: true, enabled: true, required_scopes: [], timeout_seconds: 5,
  max_output_bytes: 100, parameters: [], grantees: ["bot"],
};
const DETAIL = {
  id: "demo.show", enabled: true, current_version: 1, versions: [], spec: {}, yaml: "id: demo.show\n",
  tools: [TOOL],
};

describe("writes", () => {
  it("hides every write control from a viewer", async () => {
    serve((url) => {
      if (url.endsWith("/session")) return json(200, SESSION);
      if (url.endsWith("/tools/demo.show")) return json(200, DETAIL, { ETag: '"r1"' });
      return undefined;
    });
    renderAt("/tools/demo.show");
    expect(await screen.findByText("Definition (YAML)")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /edit|delete|disable/i })).toBeNull();
  });

  it("saves a tool with CSRF and the ETag it read, and shows a conflict on 412", async () => {
    const sent: { method?: string; headers: Record<string, string>; body: unknown }[] = [];
    serve((url, init) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/tools/demo.show") && !init.method) return json(200, DETAIL, { ETag: '"r1"' });
      if (url.endsWith("/tools/demo.show") && init.method === "PUT") {
        sent.push({ method: init.method, headers: init.headers as Record<string, string>, body: JSON.parse(String(init.body)) });
        return json(412, { error: "The resource changed since you loaded it." });
      }
      return undefined;
    });
    renderAt("/tools/demo.show/edit");
    const user = userEvent.setup();
    const editor = await screen.findByLabelText("Definition (YAML)");
    await user.clear(editor);
    await user.type(editor, "id: demo.show{enter}title: New");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Changed elsewhere.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reload" })).toBeInTheDocument();
    const [put] = sent;
    expect(sent).toHaveLength(1);
    expect(put?.headers["X-CSRF-Token"]).toBe("tok");
    expect(put?.headers["If-Match"]).toBe('"r1"');
    expect(put?.body).toEqual({ yaml: "id: demo.show\ntitle: New" });
  });

  it("asks before deleting, and shows who keeps a dangling grant", async () => {
    let deleted = false;
    serve((url, init) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/tools/demo.show") && !init.method) return json(200, DETAIL, { ETag: '"r1"' });
      if (url.endsWith("/tools/demo.show") && init.method === "DELETE") {
        deleted = true;
        return json(200, { revision: "r2" }, { ETag: '"r2"' });
      }
      if (url.endsWith("/tools")) return json(200, { tools: [], rejected: [], disabled_by_tier1: [], toolkits: [] });
      return undefined;
    });
    renderAt("/tools/demo.show");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    expect(deleted).toBe(false);
    expect(screen.getByText(/dangling grant: bot/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Yes, delete" }));
    await waitFor(() => expect(deleted).toBe(true));
    expect(await screen.findByText("No toolkits configured.")).toBeInTheDocument();
  });

  it("shows a new identity's token once, as text", async () => {
    let created: unknown;
    serve((url, init) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/identities") && !init.method) return json(200, [], { ETag: '"i1"' });
      if (url.endsWith("/identities") && init.method === "POST") {
        created = JSON.parse(String(init.body));
        expect((init.headers as Record<string, string>)["If-Match"]).toBe('"i1"');
        return json(201, { identity: "newbot", token: "gk_<b>secret</b>", revision: "i2" }, { ETag: '"i2"' });
      }
      if (url.endsWith("/tools")) return json(200, { tools: [TOOL], rejected: [], disabled_by_tier1: [], toolkits: [] });
      return undefined;
    });
    renderAt("/identities");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "New identity" }));
    await user.type(screen.getByLabelText("ID"), "newbot");
    await user.click(await screen.findByRole("checkbox"));
    await user.type(screen.getByLabelText("Scopes, one per line"), "stack:a{enter}{enter}stack:b");
    await user.click(screen.getByRole("button", { name: "Create and issue token" }));
    expect(await screen.findByTestId("one-time-secret")).toHaveTextContent("gk_<b>secret</b>");
    expect(created).toEqual({
      id: "newbot", role: "agent", tools: ["demo.show"], scopes: ["stack:a", "stack:b"], password: "",
    });
  });

  it("shows a rotated token in its own card with a copy button, and rotates once per click", async () => {
    const BOT = {
      id: "bot", role: "agent", console: "api_only", tools: [], scopes: [], unknown_tools: [],
    };
    let rotations = 0;
    serve((url, init) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/identities") && !init.method) return json(200, [BOT], { ETag: `"i${rotations}"` });
      if (url.endsWith("/identities/bot/token") && init.method === "POST") {
        rotations += 1;
        return json(200, { identity: "bot", token: `gk_new${rotations}`, revision: `i${rotations}` }, { ETag: `"i${rotations}"` });
      }
      return undefined;
    });
    renderAt("/identities");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Rotate token" }));
    await user.click(screen.getByRole("button", { name: "Yes, rotate token" }));
    const secret = await screen.findByTestId("one-time-secret");
    expect(secret).toHaveTextContent("gk_new1");
    // In the card that was clicked, not at the top of the page.
    expect(secret.closest("div.shadow-xs")).toHaveTextContent("Granted tools");
    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe("gk_new1");
    expect(screen.getByRole("button", { name: "Copied" })).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("button", { name: "Yes, rotate token" })).toBeNull());
    expect(screen.getByRole("button", { name: "Rotate token" })).toBeInTheDocument();
    expect(rotations).toBe(1);
  });

  it("takes a credential value in a password field and never renders it", async () => {
    let body: Record<string, unknown> = {};
    serve((url, init) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/credentials") && !init.method) {
        return json(200, { configured: true, dangling: [], credentials: [] }, { ETag: '"0"' });
      }
      if (url.endsWith("/credentials") && init.method === "POST") {
        body = JSON.parse(String(init.body)) as Record<string, unknown>;
        return json(201, { revision: "c1" }, { ETag: '"c1"' });
      }
      return undefined;
    });
    renderAt("/credentials");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "New credential" }));
    await user.type(screen.getByLabelText("Name"), "demo-key");
    const value = screen.getByLabelText(/^Value/);
    expect(value).toHaveAttribute("type", "password");
    await user.type(value, "sk-123");
    await user.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(body.value).toBe("sk-123"));
    expect(body).toMatchObject({ name: "demo-key", kind: "bearer", header: null, probe_url: null });
    expect(screen.queryByText("sk-123")).toBeNull();
  });
});

const PENDING = {
  id: "p1", action: "grant_set", actor: "hermes", payload: {}, base_rev: "r", status: "pending",
  created_at: "2026-10-10T10:00:00+0000", decided_by: null, decided_at: null, reason: null,
  review: {
    headline: "identity bot: +1 -0, 0 unchanged <img src=x>", unchanged: 0, stale: null,
    tools: [{ id: "demo.ghost", marker: "+", state: "missing", title: "", category: "" }],
  },
};
const PROPOSAL = {
  id: "t1", name: "zfs", spec: { executor: "local" }, actor: "hermes", kind: "create", status: "pending",
  created_at: "2026-10-10T10:00:00+0000", decided_by: null, decided_at: null, reason: null, current: null,
  spec_yaml: "zfs:\n  executor: local\n",
};

describe("requests", () => {
  it("renders a proposal's review as text and approves it with CSRF", async () => {
    let approved: RequestInit | undefined;
    serve((url, init) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/requests/pending?status=pending")) return json(200, approved ? [] : [PENDING]);
      if (url.includes("/requests/decided")) {
        const entries = approved ? [{ ...PENDING, status: "approved" }] : [];
        return json(200, { entries, next_cursor: null, total: entries.length });
      }
      if (url.endsWith("/requests/toolkits")) return json(200, []);
      if (url.endsWith("/requests/pending/p1/approve")) {
        approved = init;
        return json(200, { id: "p1", status: "approved" });
      }
      return json(200, {});
    });
    renderAt("/requests");
    expect(await screen.findByText(/<img src=x>/)).toBeInTheDocument();
    expect(screen.getByText("no such tool in the catalog")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(approved).toBeDefined());
    expect((approved?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("tok");
    expect(await screen.findByText("Nothing pending.")).toBeInTheDocument();
    expect(await screen.findByText("Archive (1)")).toBeInTheDocument();
  });

  it("loads the archive a page at a time from /requests/decided", async () => {
    const asked: string[] = [];
    serve((url) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/requests/pending?status=pending")) return json(200, []);
      if (url.includes("/requests/decided")) {
        asked.push(url);
        return url.includes("cursor=c1")
          ? json(200, { entries: [{ ...PENDING, id: "p2", status: "stale" }], next_cursor: null, total: 2 })
          : json(200, { entries: [{ ...PENDING, status: "rejected" }], next_cursor: "c1", total: 2 });
      }
      if (url.endsWith("/requests/toolkits")) return json(200, []);
      return json(200, {});
    });
    renderAt("/requests");
    expect(await screen.findByText("Archive (2)")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Show" }));
    expect(await screen.findByText("rejected")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Older" }));
    expect(await screen.findByText("stale")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Older" })).not.toBeInTheDocument();
    expect(asked.at(-1)).toContain("cursor=c1");
  });

  it("deploys a toolkit only after the acknowledgement is ticked", async () => {
    let body: unknown;
    serve((url, init) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/requests/pending?status=pending")) return json(200, []);
      if (url.endsWith("/requests/toolkits")) return json(200, [PROPOSAL]);
      if (url.endsWith("/requests/toolkits/t1/deploy")) {
        body = JSON.parse(String(init.body));
        return json(200, { id: "t1", status: "deployed" });
      }
      return json(200, {});
    });
    renderAt("/requests?tab=toolkit");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Approve and deploy" }));
    const submit = screen.getAllByRole("button", { name: "Approve and deploy" }).at(-1);
    expect(submit).toBeDisabled();
    await user.click(screen.getByRole("checkbox"));
    expect(submit).toBeEnabled();
    if (submit) await user.click(submit);
    await waitFor(() => expect(body).toEqual({ confirm: true }));
  });
});

const STATS = {
  window: "7d", label: "Last 7 days", truncated: false,
  windows: [{ key: "24h", label: "Last 24 hours" }, { key: "7d", label: "Last 7 days" }, { key: "30d", label: "Last 30 days" }],
  totals: { ok: 3, denied: 1, failed: 0, total: 4, error_rate: 25 },
  success_rate: 75, active_identities: 1, active_toolkits: 1, admin_total: 2,
  series: [{ start: "2026-10-10T00:00:00+00:00", ok: 3, not_ok: 1 }],
  toolkits: [{ name: "demo", ok: 3, denied: 1, failed: 0, total: 4 }],
  identities: [{ name: "bot", ok: 3, denied: 1, failed: 0, total: 4 }],
  admin: [{ action: "tool saved", count: 2 }],
  latency: [{ toolkit: "demo", avg_ms: 12, p95_ms: 40, count: 3 }],
};

describe("stats and docs", () => {
  it("asks for the window in the URL and shows its tables", async () => {
    const asked: string[] = [];
    serve((url) => {
      if (url.endsWith("/session")) return json(200, SESSION);
      if (url.includes("/stats")) { asked.push(url); return json(200, STATS); }
      return json(200, []);
    });
    renderAt("/stats?window=7d");
    expect(await screen.findByText("p95")).toBeInTheDocument();
    expect(asked[0]).toContain("window=7d");
    expect(screen.getByRole("link", { name: "bot" })).toHaveAttribute("href", "/audit?identity=bot");
    expect(screen.getByText("tool saved")).toBeInTheDocument();
  });

  it("renders a bundled document as elements", async () => {
    serve((url) => {
      if (url.endsWith("/session")) return json(200, SESSION);
      if (url.endsWith("/documents")) return json(200, [{ slug: "readme", label: "README", available: true }]);
      if (url.endsWith("/documents/readme")) {
        return json(200, { slug: "readme", label: "README", text: "# gatekeeper\n\n<script>alert(1)</script>" });
      }
      return json(200, []);
    });
    renderAt("/docs");
    expect(await screen.findByRole("heading", { name: "gatekeeper" })).toBeInTheDocument();
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
  });
});

describe("oauth", () => {
  const CREDS = { configured: true, dangling: [], credentials: [] };

  it("starts a flow and links to the provider's consent page", async () => {
    let body: unknown;
    serve((url, init) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/credentials")) return json(200, CREDS, { ETag: '"1"' });
      if (url.endsWith("/oauth/providers")) {
        return json(200, [{ key: "google", label: "Google", credentials: ["gmail"], callback_path: "/ui/oauth/google/callback" }]);
      }
      if (url.endsWith("/oauth/google/authorize") && init.method === "POST") {
        body = JSON.parse(String(init.body));
        return json(200, {
          provider: "google", label: "Google", credential: "gmail",
          consent_url: "https://accounts.google.com/o/oauth2/v2/auth?state=s",
          callback_uri: "https://gk.example/ui/oauth/google/callback",
          scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
          registration_console: "Google Cloud console", mismatch_error: "redirect_uri_mismatch",
        });
      }
      return json(200, []);
    });
    renderAt("/credentials");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Connect Google/ }));
    const go = await screen.findByRole("link", { name: /Continue to Google/ });
    expect(body).toEqual({ credential: "gmail" });
    expect(go).toHaveAttribute("href", "https://accounts.google.com/o/oauth2/v2/auth?state=s");
    expect(screen.getByText("https://gk.example/ui/oauth/google/callback")).toBeInTheDocument();
  });

  it("shows the console's own text for a result code, never the URL's", async () => {
    serve((url) => {
      if (url.endsWith("/session")) return json(200, SESSION);
      if (url.endsWith("/credentials")) return json(200, CREDS);
      return json(200, []);
    });
    renderAt("/credentials?oauth=%3Cb%3Eevil%3C%2Fb%3E&provider=google&credential=gmail");
    expect(await screen.findByText(/The sign-in did not complete/)).toBeInTheDocument();
    expect(screen.queryByText(/evil/)).toBeNull();
  });
});

describe("ui review fixes", () => {
  it("shows what a tool does and who holds it before the YAML, and says when it takes no parameters", async () => {
    serve((url) => {
      if (url.endsWith("/session")) return json(200, ADMIN);
      if (url.endsWith("/tools/demo.show")) return json(200, DETAIL, { ETag: '"r1"' });
      return undefined;
    });
    renderAt("/tools/demo.show");
    expect(await screen.findByText(/None: the agent calls it without arguments/)).toBeInTheDocument();
    expect(screen.getByText("Show")).toBeInTheDocument();
    expect(screen.getByText("bot")).toBeInTheDocument();
    // Edit is a link styled as a button, not a <button> nested in an <a>.
    const edit = screen.getByRole("link", { name: "Edit" });
    expect(edit).toHaveAttribute("href", "/tools/demo.show/edit");
    expect(edit.querySelector("button")).toBeNull();
  });

  it("filters the tool list and keeps the filter in the URL", async () => {
    const other = { ...TOOL, id: "demo.restart", title: "Restart", category: "write", grantees: [] };
    serve((url) => {
      if (url.endsWith("/session")) return json(200, SESSION);
      if (url.endsWith("/tools")) {
        return json(200, {
          tools: [TOOL, other], rejected: [], disabled_by_tier1: [],
          toolkits: [{ name: "demo", executor: "local" }],
        });
      }
      return undefined;
    });
    renderAt("/tools");
    const user = userEvent.setup();
    expect(await screen.findByText("demo.restart")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Filter tools"), "restart");
    expect(screen.queryByText("demo.show")).toBeNull();
    expect(screen.getByText("demo.restart")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Filter tools"));
    await user.type(screen.getByLabelText("Filter tools"), "nothing-like-this");
    expect(screen.getByText(/No tool matches/)).toBeInTheDocument();
  });

  it("clears the audit filter", async () => {
    const asked: string[] = [];
    serve((url) => {
      if (url.endsWith("/session")) return json(200, SESSION);
      if (url.includes("/audit")) {
        asked.push(url);
        return json(200, { entries: [], next_cursor: null, window_truncated: false });
      }
      return undefined;
    });
    renderAt("/audit?identity=bot");
    const user = userEvent.setup();
    expect(await screen.findByLabelText("Identity")).toHaveValue("bot");
    await user.click(screen.getByRole("button", { name: "Clear" }));
    await waitFor(() => expect(screen.getByLabelText("Identity")).toHaveValue(""));
    expect(asked.at(-1)).not.toContain("identity=");
    expect(screen.queryByRole("button", { name: "Clear" })).toBeNull();
  });

  it("shows where a failed /mcp sign-in came from, in the audit log and the feed", async () => {
    const failure = {
      ts: "2026-10-11T17:05:04Z", kind: "auth_failure", reason: "unknown_token",
      detail: "POST /mcp from 10.10.110.102", client: "10.10.110.102", fingerprint: "a1b2c3d4e5f6",
      method: "POST", path: "/mcp", user_agent: "python-httpx/0.28",
    };
    serve((url) => {
      if (url.endsWith("/session")) return json(200, SESSION);
      if (url.includes("/audit")) return json(200, { entries: [failure], next_cursor: null, window_truncated: false });
      return undefined;
    });
    renderAt("/audit");
    expect(await screen.findByText("unknown_token · from 10.10.110.102 · token a1b2c3d4e5f6 · python-httpx/0.28")).toBeInTheDocument();
    // Who and What are filled in, not blank.
    expect(screen.getByText("10.10.110.102")).toBeInTheDocument();
    expect(screen.getByText("POST /mcp")).toBeInTheDocument();
    const { describeEvent } = await import("@/pages/events");
    expect(describeEvent(failure).text).toBe("Sign-in failed (unknown_token) from 10.10.110.102");
  });

  it("names what an agent proposed in the overview feed, not its random ID", async () => {
    const { describeEvent } = await import("@/pages/events");
    expect(describeEvent({
      kind: "admin_change", actor: "orchestrator", action: "pending_propose", target: "W62JG2Wr01", proposed_action: "tool_enable",
    }).text).toBe("orchestrator proposed tool_enable");
    expect(describeEvent({ kind: "admin_change", actor: "root", action: "toolkit_deploy", target: "paperless" }).text)
      .toBe("root deployed toolkit paperless");
  });
});
