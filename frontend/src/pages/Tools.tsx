import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, LayoutGrid, Pencil, Plus, Search, Table2 } from "lucide-react";
import { API_BASE, apiGet, apiSend, etagFor, type Schemas } from "@/api/client";
import { useCanWrite } from "@/auth";
import { ConfirmButton, Textarea, useWrite, WriteError } from "@/components/forms";
import { PageHeader } from "@/components/Layout";
import { Badge, Pills } from "@/components/ui/badge";
import { Button, LinkButton } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { CodeBlock, CopyButton } from "@/components/ui/copy";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { Input } from "@/components/ui/input";
import { Row } from "./Identities";

type Tool = Schemas["Tool"];

export function Tools() {
  const canWrite = useCanWrite();
  const [params, setParams] = useSearchParams();
  const matrix = params.get("view") === "matrix";
  const filter = params.get("q") ?? "";
  const query = useQuery({ queryKey: ["tools"], queryFn: () => apiGet("/tools") });
  if (query.isPending) return <Loading />;
  if (query.isError) return <QueryError error={query.error} />;
  const { rejected, toolkits } = query.data;
  const tools = filterTools(query.data.tools, filter);
  const setFilter = (q: string) => {
    const next = new URLSearchParams(params);
    if (q) next.set("q", q); else next.delete("q");
    setParams(next, { replace: true });
  };

  const byToolkit = new Map<string, Tool[]>();
  for (const tool of tools) {
    const list = byToolkit.get(tool.toolkit) ?? [];
    list.push(tool);
    byToolkit.set(tool.toolkit, list);
  }

  return (
    <>
      <PageHeader
        title="Tools"
        subtitle="Defining and granting are two separate steps: a tool with no grantees exists, but is invisible to every agent."
        actions={
          <div className="flex gap-1">
            {canWrite && toolkits.length > 0 && (
              <LinkButton to="/tools/new" size="sm"><Plus className="size-3.5" /> New tool</LinkButton>
            )}
            <LinkButton to="/tools/integrations" variant="outline" size="sm">Integrations</LinkButton>
            <Button size="sm" variant={matrix ? "outline" : "default"} onClick={() => setParams(filter ? { q: filter } : {})}>
              <LayoutGrid className="size-3.5" /> Cards
            </Button>
            <Button size="sm" variant={matrix ? "default" : "outline"} onClick={() => setParams(filter ? { view: "matrix", q: filter } : { view: "matrix" })}>
              <Table2 className="size-3.5" /> Matrix
            </Button>
          </div>
        }
      />
      {rejected.length > 0 && (
        <Notice tone="bad">
          <strong>Rejected by Tier 1 and therefore not loaded.</strong> They stay in the file so they can be fixed:
          <ul className="list-disc pl-5">
            {rejected.map((r) => <li key={r.id}><code>{r.id}</code> – {r.reason}</li>)}
          </ul>
        </Notice>
      )}
      {query.data.tools.length > 0 && (
        <span className="relative block max-w-sm">
          <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" aria-hidden />
          <Input
            type="search" aria-label="Filter tools" placeholder="Filter by ID, title, toolkit or grantee…"
            className="w-full pl-8" value={filter} onChange={(e) => setFilter(e.target.value)}
          />
        </span>
      )}
      {toolkits.length === 0 ? (
        <Notice>
          <strong>No toolkits configured.</strong> A tool always binds to a Tier 1 toolkit, and toolkits
          are a deploy-time decision (FR-4.11).
        </Notice>
      ) : query.data.tools.length > 0 && tools.length === 0 ? (
        <p className="text-sm text-muted-foreground">No tool matches “{filter}”.</p>
      ) : tools.length === 0 ? (
        <Notice>
          <strong>No tools yet.</strong> gatekeeper ships an empty catalog on purpose: every capability is a
          deliberate decision that lands in the audit log.
        </Notice>
      ) : matrix ? (
        <ToolMatrix tools={tools} />
      ) : (
        [...byToolkit.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([kit, list]) => (
          <section key={kit} className="space-y-2">
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <span className="font-mono">{kit}</span>
              <Badge>{toolkits.find((t) => t.name === kit)?.executor}</Badge>
              <Badge tone="ok">{list.filter((t) => t.category === "read").length} read</Badge>
              <Badge tone="warn">{list.filter((t) => t.category !== "read").length} write</Badge>
            </h2>
            <div className="grid gap-3 md:grid-cols-2">
              {list.map((tool) => <ToolCard key={tool.id} tool={tool} />)}
            </div>
          </section>
        ))
      )}
    </>
  );
}

function filterTools(tools: Tool[], filter: string): Tool[] {
  const q = filter.trim().toLowerCase();
  if (!q) return tools;
  return tools.filter((t) =>
    [t.id, t.title, t.toolkit, t.category, ...t.grantees].some((v) => v.toLowerCase().includes(q)));
}

/** The definition ID a concrete tool came from -- `x.y@dest` -> `x.y`. */
export function baseId(id: string): string {
  const at = id.indexOf("@");
  return at === -1 ? id : id.slice(0, at);
}

function ToolCard({ tool }: { tool: Tool }) {
  return (
    <Card>
      <CardHeader
        title={<Link className="font-mono hover:underline" to={`/tools/${encodeURIComponent(baseId(tool.id))}`}>{tool.id}</Link>}
        actions={
          <span className="flex gap-1">
            <Badge tone={tool.category === "read" ? "ok" : "warn"}>{tool.category}</Badge>
            {!tool.enabled && <Badge tone="deny">disabled</Badge>}
          </span>
        }
      />
      <CardBody className="space-y-2 text-sm">
        <p className="font-medium">{tool.title}</p>
        <p className="text-muted-foreground">{tool.description}</p>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Granted to</span>
          <Pills values={tool.grantees} tone="ok" empty="nobody" />
        </div>
        {tool.required_scopes.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted-foreground">Scopes</span>
            <Pills values={tool.required_scopes} tone="accent" />
          </div>
        )}
      </CardBody>
    </Card>
  );
}

function ToolMatrix({ tools }: { tools: Tool[] }) {
  return (
    <Card className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-left text-xs text-muted-foreground">
          <tr>
            {["Tool", "Category", "Enabled", "Parameters", "Grantees"].map((h) => (
              <th key={h} className="px-3 py-2 font-medium">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {tools.map((tool) => (
            <tr key={tool.id} className="border-t border-border">
              <td className="px-3 py-2 font-mono">
                <Link className="hover:underline" to={`/tools/${encodeURIComponent(baseId(tool.id))}`}>{tool.id}</Link>
              </td>
              <td className="px-3 py-2"><Badge tone={tool.category === "read" ? "ok" : "warn"}>{tool.category}</Badge></td>
              <td className="px-3 py-2">{tool.enabled ? "yes" : <Badge tone="deny">no</Badge>}</td>
              <td className="px-3 py-2"><Pills values={tool.parameters.map((p) => p.name)} /></td>
              <td className="px-3 py-2"><Pills values={tool.grantees} tone="ok" empty="nobody" /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

export function ToolDetail() {
  const { toolId = "" } = useParams();
  const canWrite = useCanWrite();
  const navigate = useNavigate();
  const query = useQuery({
    queryKey: ["tool", toolId],
    queryFn: () => apiGet("/tools/{tool_id}", { path: { tool_id: toolId } }),
  });
  const self = `/tools/${encodeURIComponent(toolId)}`;
  const toggle = useWrite(
    (enabled: boolean) => apiSend("PUT", `${self}/enabled`, { body: { enabled }, ifMatchOf: self }),
    [["tool", toolId], ["tools"], ["overview"]],
  );
  const remove = useWrite(
    () => apiSend("DELETE", self, { ifMatchOf: self }),
    [["tools"], ["overview"]],
    () => void navigate("/tools"),
  );
  const holders = query.data
    ? [...new Set(query.data.tools.flatMap((t) => t.grantees))].sort()
    : [];
  return (
    <>
      <Link to="/tools" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> Tools
      </Link>
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        <>
          <PageHeader
            title={query.data.id}
            subtitle={`Version ${query.data.current_version ?? "?"}${query.data.enabled ? "" : " · disabled"}`}
            actions={canWrite && (
              <div className="flex flex-wrap items-start gap-1">
                <LinkButton to={`${self}/edit`} size="sm"><Pencil className="size-3.5" /> Edit</LinkButton>
                <Button
                  size="sm" variant="outline" disabled={toggle.isPending}
                  onClick={() => toggle.mutate(!query.data.enabled)}
                >
                  {query.data.enabled ? "Disable" : "Enable"}
                </Button>
                <ConfirmButton
                  label="Delete" question={`Delete ${query.data.id}?`}
                  busy={remove.isPending} onConfirm={() => remove.mutateAsync(undefined)}
                >
                  <span className="text-xs text-muted-foreground">
                    The full definition goes to the audit log.
                    {holders.length > 0 && ` These identities keep a dangling grant: ${holders.join(", ")}.`}
                  </span>
                </ConfirmButton>
              </div>
            )}
          />
          <WriteError error={toggle.error ?? remove.error} onReload={() => void query.refetch()} />
          {query.data.tools.map((tool) => <ToolSummary key={tool.id} tool={tool} />)}
          <Card>
            <CardHeader title="Definition (YAML)" actions={<CopyButton text={query.data.yaml} />} />
            <CardBody><CodeBlock text={query.data.yaml} /></CardBody>
          </Card>
        </>
      )}
    </>
  );
}

/** What a reviewer wants before the YAML: what it does, who holds it, and
 *  what an agent must pass. */
function ToolSummary({ tool }: { tool: Tool }) {
  return (
    <Card>
      <CardHeader
        title={<span className="font-mono">{tool.id}</span>}
        actions={
          <span className="flex flex-wrap gap-1">
            <Badge tone={tool.category === "read" ? "ok" : "warn"}>{tool.category}</Badge>
            {!tool.enabled && <Badge tone="deny">disabled</Badge>}
          </span>
        }
      />
      <CardBody className="space-y-2 text-sm">
        <p className="font-medium">{tool.title}</p>
        {tool.description && <p className="text-muted-foreground">{tool.description}</p>}
        <Row label="Toolkit"><code>{tool.toolkit}</code>{tool.destination && <> → <code>{tool.destination}</code></>}</Row>
        <Row label="Granted to"><Pills values={tool.grantees} tone="ok" empty="nobody" /></Row>
        {tool.required_scopes.length > 0 && <Row label="Scopes"><Pills values={tool.required_scopes} tone="accent" /></Row>}
        <Row label="Limits">
          <Pills values={[`timeout ${tool.timeout_seconds}s`, `output ≤ ${tool.max_output_bytes} B`, tool.idempotent ? "idempotent" : "not idempotent"]} />
        </Row>
        <Row label="Parameters">
          {tool.parameters.length === 0 ? (
            <span className="text-muted-foreground">None: the agent calls it without arguments.</span>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs text-muted-foreground">
                  <tr>{["Parameter", "Type", "Rule", "Description"].map((h) => <th key={h} className="py-1 pr-3 font-medium">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {tool.parameters.map((p) => (
                    <tr key={p.name} className="border-t border-border align-top">
                      <td className="py-1.5 pr-3 font-mono whitespace-nowrap">{p.name}{p.required && " *"}</td>
                      <td className="py-1.5 pr-3">{p.type}</td>
                      <td className="py-1.5 pr-3 font-mono text-xs wrap-anywhere">
                        {p.derived ? <Badge tone="ok">derived</Badge> : p.pattern ?? (p.values.length ? p.values.join(" | ") : "")}
                      </td>
                      <td className="py-1.5 text-muted-foreground">{p.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Row>
      </CardBody>
    </Card>
  );
}

export function Integrations() {
  const canWrite = useCanWrite();
  const query = useQuery({ queryKey: ["integrations"], queryFn: () => apiGet("/integrations") });
  return (
    <>
      <PageHeader
        title="Integrations"
        subtitle="Starter tools per service. Picking one only pre-fills the tool editor; the toolkit itself always stays a deploy-time edit (FR-4.11)."
      />
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {query.data.map((it) => (
            <Card key={it.key}>
              <CardBody className="space-y-2">
                <div className="flex items-center gap-2">
                  <img src={`${API_BASE}/integrations/${encodeURIComponent(it.key)}/logo.svg`} alt="" className="size-7" />
                  <span className="font-medium">{it.display_name}</span>
                  <span className="flex-1" />
                  <Badge tone={it.toolkit_configured ? "ok" : "neutral"}>
                    {it.toolkit_configured ? "toolkit configured" : "no toolkit"}
                  </Badge>
                </div>
                {it.notes && <p className="text-xs text-muted-foreground">{it.notes}</p>}
                {canWrite && it.toolkit_configured ? (
                  <ul className="space-y-1 text-sm">
                    {it.tools.map((t) => (
                      <li key={t.id} className="flex items-center gap-2">
                        <code className="flex-1 truncate text-xs">{t.id}</code>
                        {t.exists ? <Badge tone="ok">added</Badge> : (
                          <Link
                            className="text-xs text-primary hover:underline"
                            to={`/tools/new?integration=${encodeURIComponent(it.key)}&tool=${encodeURIComponent(t.id)}`}
                          >
                            Add
                          </Link>
                        )}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Pills values={it.tools.map((t) => t.id)} />
                )}
              </CardBody>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}

/** The YAML editor for a new definition or an existing one. The server
 *  checks it against Tier 1 on save, exactly as the classic form does; an
 *  integration only pre-fills it. */
export function ToolEditor() {
  const { toolId } = useParams();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const editing = toolId !== undefined;
  const self = editing ? `/tools/${encodeURIComponent(toolId)}` : "/tools";
  const integration = params.get("integration");
  const fromTool = params.get("tool");

  const source = useQuery({
    queryKey: ["tool-editor", toolId ?? "", integration ?? "", fromTool ?? ""],
    // Also the read whose ETag the save sends back as If-Match.
    // The ETag is kept with the text it belongs to. The shared one in the
    // client moves whenever another query rereads the same URL, and live
    // updates do that while this editor is open: saving with it would
    // overwrite a concurrent change instead of answering 412.
    queryFn: async () => {
      if (editing) {
        const yaml = (await apiGet("/tools/{tool_id}", { path: { tool_id: toolId } })).yaml;
        return { yaml, etag: etagFor(self) };
      }
      await apiGet("/tools");
      const etag = etagFor(self);
      if (integration && fromTool) {
        const all = await apiGet("/integrations");
        const spec = all.find((i) => i.key === integration)?.tools.find((t) => t.id === fromTool);
        if (spec) return { yaml: spec.yaml, etag };
      }
      return { yaml: (await apiGet("/tool-scaffold")).yaml, etag };
    },
    staleTime: Infinity,
    gcTime: 0,
  });

  const [text, setText] = useState<string | null>(null);
  const value = text ?? source.data?.yaml ?? "";
  const save = useWrite(
    (yaml: string) =>
      apiSend<Schemas["ToolSaved"]>(editing ? "PUT" : "POST", self, { body: { yaml }, ifMatch: source.data?.etag }),
    [["tools"], ["tool"], ["overview"], ["integrations"]],
    (saved) => void navigate(`/tools/${encodeURIComponent(saved.id)}`),
  );

  return (
    <>
      <Link to={editing ? self : "/tools"} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> {editing ? toolId : "Tools"}
      </Link>
      <PageHeader
        title={editing ? `Edit ${toolId}` : "New tool"}
        subtitle="The definition is checked against Tier 1 before it is stored."
      />
      {source.isPending ? <Loading /> : source.isError ? <QueryError error={source.error} /> : (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate(value);
          }}
        >
          <WriteError
            error={save.error}
            onReload={() => {
              setText(null);
              save.reset();
              void source.refetch();
            }}
          />
          <Textarea
            aria-label="Definition (YAML)"
            className="min-h-[28rem] w-full font-mono text-xs"
            spellCheck={false}
            // YAML: a soft-wrapped line reads as a new key.
            wrap="off"
            value={value}
            onChange={(e) => setText(e.target.value)}
          />
          <div className="flex gap-2">
            <Button type="submit" disabled={save.isPending}>{editing ? "Save" : "Create"}</Button>
            <LinkButton to={editing ? self : "/tools"} variant="ghost">Cancel</LinkButton>
          </div>
        </form>
      )}
    </>
  );
}
