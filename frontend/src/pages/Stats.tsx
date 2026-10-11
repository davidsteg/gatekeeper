import { Link, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiGet, type Schemas } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { cn } from "@/lib/utils";
import { POLL_MS, TOOLTIP_STYLE } from "./Overview";

type Stats = Schemas["Stats"];
type Window = "24h" | "7d" | "30d";
const WINDOWS: Window[] = ["24h", "7d", "30d"];

export function Stats() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("window");
  const window: Window = WINDOWS.includes(raw as Window) ? (raw as Window) : "24h";
  const query = useQuery({
    queryKey: ["stats", window],
    queryFn: () => apiGet("/stats", { query: { window } }),
    refetchInterval: POLL_MS,
  });
  return (
    <>
      <PageHeader
        title="Stats"
        subtitle="Calls, outcomes and latency from the audit log."
        actions={
          <div role="tablist" aria-label="Window" className="flex gap-1">
            {(query.data?.windows ?? WINDOWS.map((key) => ({ key, label: key }))).map((w) => (
              <button
                key={w.key} role="tab" aria-selected={w.key === window}
                onClick={() => setParams(w.key === "24h" ? {} : { window: w.key })}
                className={cn(
                  "rounded-md px-3 py-1.5 text-sm",
                  w.key === window ? "bg-primary/10 font-medium text-primary" : "hover:bg-muted",
                )}
              >
                {w.key}
              </button>
            ))}
          </div>
        }
      />
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : <StatsBody data={query.data} />}
    </>
  );
}

function StatsBody({ data }: { data: Stats }) {
  return (
    <>
      {data.truncated && (
        <Notice>
          Counted over the most recent part of the audit log only; older records in this window are not included.
        </Notice>
      )}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Tile n={data.totals.total} label="calls" />
        <Tile n={`${data.success_rate}%`} label="succeeded" />
        <Tile n={data.totals.denied} label="denied" tone={data.totals.denied ? "deny" : undefined} />
        <Tile n={data.totals.failed} label="failed" tone={data.totals.failed ? "deny" : undefined} />
        <Tile n={data.admin_total} label="admin actions" />
      </div>
      <Card>
        <CardHeader
          title={`Activity, ${data.label.toLowerCase()}`}
          actions={
            <span className="text-xs text-muted-foreground">
              {data.active_identities} identities · {data.active_toolkits} toolkits active
            </span>
          }
        />
        <CardBody><SeriesChart data={data} /></CardBody>
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <CountTable title="By toolkit" rows={data.toolkits} empty="No tool calls in this window." />
        <CountTable title="By identity" rows={data.identities} empty="No identity made a call in this window." link />
        <Card>
          <CardHeader title="Latency" />
          <CardBody>
            {data.latency.length === 0 ? (
              <p className="text-sm text-muted-foreground">No timed calls in this window.</p>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-muted-foreground">
                    <th className="py-1 font-medium">Toolkit</th>
                    <th className="py-1 text-right font-medium">avg</th>
                    <th className="py-1 text-right font-medium">p95</th>
                    <th className="py-1 text-right font-medium">calls</th>
                  </tr>
                </thead>
                <tbody>
                  {data.latency.map((l) => (
                    <tr key={l.toolkit} className="border-t border-border">
                      <td className="py-1 font-mono">{l.toolkit}</td>
                      <td className="py-1 text-right tabular-nums">{l.avg_ms} ms</td>
                      <td className="py-1 text-right tabular-nums">{l.p95_ms} ms</td>
                      <td className="py-1 text-right tabular-nums">{l.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Admin actions" />
          <CardBody>
            {data.admin.length === 0 ? (
              <p className="text-sm text-muted-foreground">No console changes in this window.</p>
            ) : (
              <ul className="space-y-1 text-sm">
                {data.admin.map((a) => (
                  <li key={a.action} className="flex justify-between">
                    <span>{a.action}</span>
                    <span className="tabular-nums">{a.count}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>
    </>
  );
}

function Tile({ n, label, tone }: { n: number | string; label: string; tone?: "deny" }) {
  return (
    <Card className="flex items-baseline gap-2 p-4">
      <span className={cn("text-2xl font-semibold tabular-nums", tone === "deny" && "text-deny")}>{n}</span>
      <span className="text-sm text-muted-foreground">{label}</span>
    </Card>
  );
}

function bucketLabel(start: string, hourly: boolean) {
  const d = new Date(start);
  return hourly
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function SeriesChart({ data }: { data: Stats }) {
  const hourly = data.window === "24h";
  const rows = data.series.map((p) => ({ at: bucketLabel(p.start, hourly), ok: p.ok, "not ok": p.not_ok }));
  return (
    <div className="h-56" role="img" aria-label={`Calls per ${hourly ? "hour" : "day"}, ok and not ok`}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
          <CartesianGrid vertical={false} strokeOpacity={0.15} />
          <XAxis dataKey="at" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
          <YAxis allowDecimals={false} tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip cursor={{ fillOpacity: 0.08 }} {...TOOLTIP_STYLE} />
          <Bar dataKey="ok" stackId="a" fill="var(--color-ok)" />
          <Bar dataKey="not ok" stackId="a" fill="var(--color-deny)" radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function CountTable({ title, rows, empty, link }: {
  title: string;
  rows: Schemas["StatsRow"][];
  empty: string;
  link?: boolean;
}) {
  const max = Math.max(1, ...rows.map((r) => r.total));
  return (
    <Card>
      <CardHeader title={title} />
      <CardBody>
        {rows.length === 0 ? <p className="text-sm text-muted-foreground">{empty}</p> : (
          <ul className="space-y-2 text-sm">
            {rows.map((r) => (
              <li key={r.name}>
                <div className="flex justify-between gap-2">
                  {link
                    ? <Link className="font-mono hover:underline" to={`/audit?identity=${encodeURIComponent(r.name)}`}>{r.name}</Link>
                    : <span className="font-mono">{r.name === "_unknown" ? "unknown tool" : r.name}</span>}
                  <span className="text-xs text-muted-foreground tabular-nums">
                    {r.total} · {r.ok} ok · {r.denied} denied · {r.failed} failed
                  </span>
                </div>
                <div className="mt-1 flex h-1.5 overflow-hidden rounded bg-muted" aria-hidden>
                  <span className="bg-ok" style={{ width: `${(r.ok / max) * 100}%` }} />
                  <span className="bg-deny" style={{ width: `${((r.denied + r.failed) / max) * 100}%` }} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}
