import { useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Ban, KeyRound, Lock, Search, SlidersHorizontal } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiGet, type Schemas } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { cn, formatTime } from "@/lib/utils";
import { usePollInterval } from "@/live";
import { describeEvent } from "./events";


/** Recharts draws its tooltip white on white-ish text in dark mode unless
 *  told otherwise; the theme tokens follow prefers-color-scheme. */
export const TOOLTIP_STYLE = {
  contentStyle: {
    background: "var(--color-card)",
    border: "1px solid var(--color-border)",
    borderRadius: 6,
    color: "var(--color-card-foreground)",
    fontSize: 12,
  },
  labelStyle: { color: "var(--color-muted-foreground)" },
} as const;

export function Overview() {
  const query = useQuery({
    queryKey: ["overview"],
    queryFn: () => apiGet("/overview"),
    refetchInterval: usePollInterval(),
  });
  if (query.isPending) return <Loading />;
  if (query.isError) return <QueryError error={query.error} />;
  const data = query.data;
  const pending = data.notices.pending_changes + data.notices.pending_toolkits;

  return (
    <>
      <PageHeader title="Overview" subtitle="Who can reach what, and what's happening right now." />
      {data.notices.unwritable.length > 0 && (
        <Notice tone="bad">
          <strong>Configuration is not writable.</strong> {data.notices.unwritable.join(", ")}.yaml sits
          on a read-only mount, so every change will be refused.
        </Notice>
      )}
      {data.notices.disabled_by_tier1.length > 0 && (
        <Notice tone="bad">
          <strong>Disabled by a Tier 1 violation.</strong>
          <ul className="list-disc pl-5">
            {data.notices.disabled_by_tier1.map((v) => <li key={v}>{v}</li>)}
          </ul>
        </Notice>
      )}
      {pending > 0 && (
        <Notice>
          <strong>{pending}</strong> request{pending === 1 ? "" : "s"} awaiting a decision. Review them
          under <Link className="underline" to="/requests">Requests</Link>.
        </Notice>
      )}
      {data.notices.no_toolkits && (
        <Notice>
          <strong>No toolkits configured.</strong> Toolkits are a deploy-time decision (FR-4.11): edit
          toolkits.yaml and redeploy.
        </Notice>
      )}
      {data.notices.empty_catalog && (
        <Notice tone="good">
          <strong>The catalog is empty, which is the state after installation.</strong> gatekeeper can
          do nothing until a tool is created.
        </Notice>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat to="/tools" icon={SlidersHorizontal} n={data.stats.tools_active} label={plural(data.stats.tools_active, "tool active", "tools active")} />
        <Stat to="/identities" icon={KeyRound} n={data.stats.identities} label={plural(data.stats.identities, "identity", "identities")} />
        <Stat to="/toolkits" icon={Lock} n={data.stats.protected_resources} label={plural(data.stats.protected_resources, "protected resource", "protected resources")} />
        <Stat
          to="/tools" icon={Ban} n={data.stats.tools_disabled} label={plural(data.stats.tools_disabled, "tool disabled", "tools disabled")}
          tone={data.stats.tools_disabled ? "deny" : undefined}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <Card>
          <CardHeader
            title="Activity, last 12 h"
            actions={
              <span className="text-xs text-muted-foreground">
                {data.outcomes.total} calls · {data.outcomes.success_pct}% ok · {data.events_logged} events
              </span>
            }
          />
          <CardBody>
            <ActivityChart activity={data.activity} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Recent events" />
          <CardBody className="max-h-72 space-y-1.5 overflow-auto">
            {data.recent.length === 0 && <p className="text-sm text-muted-foreground">No activity yet.</p>}
            {data.recent.map((record, i) => {
              const event = describeEvent(record);
              return (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", event.dot)} />
                  <span className="min-w-0 flex-1 wrap-break-word">{event.text}</span>
                  <span className="shrink-0 font-mono text-xs text-muted-foreground">{formatTime(record.ts)}</span>
                </div>
              );
            })}
          </CardBody>
        </Card>
      </div>

      <AccessMatrix access={data.access} />
    </>
  );
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

function Stat({ to, icon: Icon, n, label, tone }: {
  to: string;
  icon: typeof Ban;
  n: number;
  label: string;
  tone?: "deny";
}) {
  return (
    <Link to={to}>
      <Card className="flex flex-wrap items-center gap-x-3 gap-y-1 p-3 hover:bg-muted/50 sm:p-4">
        <Icon className={cn("size-5 text-muted-foreground", tone === "deny" && "text-deny")} aria-hidden />
        <span className="text-2xl font-semibold tabular-nums">{n}</span>
        <span className="text-sm text-muted-foreground">{label}</span>
      </Card>
    </Link>
  );
}

function ActivityChart({ activity }: { activity: Schemas["ActivityBucket"][] }) {
  const rows = activity.map((b) => ({ hour: formatTime(b.hour), ok: b.ok, "not ok": b.not_ok }));
  return (
    <div className="h-56" role="img" aria-label="Calls per hour, ok and not ok">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
          <CartesianGrid vertical={false} strokeOpacity={0.15} />
          <XAxis dataKey="hour" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
          <YAxis allowDecimals={false} tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip cursor={{ fillOpacity: 0.08 }} {...TOOLTIP_STYLE} />
          <Bar dataKey="ok" stackId="a" fill="var(--color-ok)" />
          <Bar dataKey="not ok" stackId="a" fill="var(--color-deny)" radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function AccessMatrix({ access }: { access: Schemas["AccessMatrix"] }) {
  const [filter, setFilter] = useState("");
  const q = filter.trim().toLowerCase();
  // A filter narrows whichever axis it matches: identities (by id or
  // role), toolkits (by name or executor), or both.
  const { rows, columns } = useMemo(() => {
    const all = access.toolkits.map((t, i) => ({ ...t, i }));
    if (!q) return { rows: access.rows, columns: all };
    const kits = all.filter((t) => t.name.toLowerCase().includes(q) || t.executor.toLowerCase().includes(q));
    const idents = access.rows.filter(
      (r) => r.identity.toLowerCase().includes(q) || r.role.toLowerCase().includes(q),
    );
    if (!kits.length && !idents.length) return { rows: [], columns: [] };
    return { rows: idents.length ? idents : access.rows, columns: kits.length ? kits : all };
  }, [access, q]);

  const heat = (total: number) =>
    total === 0 ? "" : total >= access.hot_threshold ? "bg-ok/40" : total >= access.hot_threshold / 2 ? "bg-ok/25" : "bg-ok/10";

  return (
    <Card>
      <CardHeader
        title="Access map"
        actions={
          <span className="relative">
            <Search className="pointer-events-none absolute top-2.5 left-2 size-4 text-muted-foreground" aria-hidden />
            <Input
              aria-label="Filter identity or toolkit" placeholder="Filter identity or toolkit…"
              className="h-8 pl-8" value={filter} onChange={(e) => setFilter(e.target.value)}
            />
          </span>
        }
      />
      <CardBody className="overflow-x-auto">
        {access.toolkits.length === 0 ? (
          <p className="text-sm text-muted-foreground">No toolkits configured yet.</p>
        ) : rows.length === 0 || columns.length === 0 ? (
          <p className="text-sm text-muted-foreground">No identity or toolkit matches “{filter}”.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th className="sticky left-0 bg-card py-2 pr-3 font-medium">Identity</th>
                <th className="py-2 pr-3 font-medium">Role</th>
                {columns.map((c) => (
                  <th key={c.name} className="px-2 py-2 text-center font-medium">
                    <div className="font-mono text-foreground">{c.name}</div>
                    <div>{c.executor}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.identity} className="border-t border-border">
                  <td className="sticky left-0 bg-card py-2 pr-3 font-mono whitespace-nowrap">{row.identity}</td>
                  <td className="py-2 pr-3">
                    <Badge tone={row.role === "admin" ? "accent" : "neutral"}>{row.role}</Badge>
                  </td>
                  {columns.map((c) => {
                    const cell = row.cells[c.i];
                    if (!cell || cell.granted.length === 0) {
                      return <td key={c.name} className="px-2 py-2 text-center text-muted-foreground">–</td>;
                    }
                    const calls = cell.calls;
                    const title =
                      `${row.identity} → ${c.name}: ${cell.granted.join(", ")}\n` +
                      (calls.total
                        ? `${calls.total} calls (${calls.ok} ok, ${calls.denied} denied, ${calls.failed} failed)`
                        : "no calls yet");
                    return (
                      <td key={c.name} className="px-2 py-2 text-center">
                        <span title={title} className={cn("inline-block min-w-8 rounded px-2 py-0.5 font-medium", heat(calls.total))}>
                          {cell.granted.length}
                        </span>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardBody>
    </Card>
  );
}
