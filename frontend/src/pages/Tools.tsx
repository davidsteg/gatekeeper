import { Link, useParams, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, LayoutGrid, Table2 } from "lucide-react";
import { API_BASE, apiGet, type Schemas } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Badge, Pills } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { CodeBlock, CopyButton } from "@/components/ui/copy";
import { Loading, Notice, QueryError } from "@/components/ui/notice";

type Tool = Schemas["Tool"];

export function Tools() {
  const [params, setParams] = useSearchParams();
  const matrix = params.get("view") === "matrix";
  const query = useQuery({ queryKey: ["tools"], queryFn: () => apiGet("/tools") });
  if (query.isPending) return <Loading />;
  if (query.isError) return <QueryError error={query.error} />;
  const { tools, rejected, toolkits } = query.data;

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
            <Link to="/tools/integrations"><Button variant="outline" size="sm">Integrations</Button></Link>
            <Button size="sm" variant={matrix ? "outline" : "default"} onClick={() => setParams({})}>
              <LayoutGrid className="size-3.5" /> Cards
            </Button>
            <Button size="sm" variant={matrix ? "default" : "outline"} onClick={() => setParams({ view: "matrix" })}>
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
      {toolkits.length === 0 ? (
        <Notice>
          <strong>No toolkits configured.</strong> A tool always binds to a Tier 1 toolkit, and toolkits
          are a deploy-time decision (FR-4.11).
        </Notice>
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
  const query = useQuery({
    queryKey: ["tool", toolId],
    queryFn: () => apiGet("/tools/{tool_id}", { path: { tool_id: toolId } }),
  });
  return (
    <>
      <Link to="/tools" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> Tools
      </Link>
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        <>
          <PageHeader title={query.data.id} subtitle={`Version ${query.data.current_version ?? "?"}`} />
          {query.data.tools.map((tool) => (
            <Card key={tool.id}>
              <CardHeader title={<span className="font-mono">{tool.id}</span>} />
              <CardBody>
                <table className="w-full text-sm">
                  <thead className="text-left text-xs text-muted-foreground">
                    <tr>{["Parameter", "Type", "Rule", "Description"].map((h) => <th key={h} className="py-1 pr-3 font-medium">{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {tool.parameters.map((p) => (
                      <tr key={p.name} className="border-t border-border align-top">
                        <td className="py-1.5 pr-3 font-mono">{p.name}{p.required && " *"}</td>
                        <td className="py-1.5 pr-3">{p.type}</td>
                        <td className="py-1.5 pr-3 font-mono text-xs break-all">
                          {p.derived ? <Badge tone="ok">derived</Badge> : p.pattern ?? (p.values.length ? p.values.join(" | ") : "")}
                        </td>
                        <td className="py-1.5 text-muted-foreground">{p.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardBody>
            </Card>
          ))}
          <Card>
            <CardHeader title="Definition (YAML)" actions={<CopyButton text={query.data.yaml} />} />
            <CardBody><CodeBlock text={query.data.yaml} /></CardBody>
          </Card>
        </>
      )}
    </>
  );
}

export function Integrations() {
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
                <Pills values={it.tools.map((t) => t.id)} />
              </CardBody>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}
