import { useEffect, useRef, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router";
import { useInfiniteQuery } from "@tanstack/react-query";
import { apiGet } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { formatTime, useIsNarrow } from "@/lib/utils";
import { usePollInterval } from "@/live";

const OUTCOMES = ["", "ok", "denied", "failed", "unknown"] as const;
type Outcome = (typeof OUTCOMES)[number];
const TONE: Record<string, Tone> = { ok: "ok", denied: "deny", failed: "deny", unknown: "warn" };

const s = (v: unknown) => (v === undefined || v === null ? "" : typeof v === "string" ? v : JSON.stringify(v));

/** The detail column. A failed sign-in spells out where it came from:
 *  address, token fingerprint and client program. Records written before
 *  1.5.0 have none of these and fall back to their own `detail`. */
function detailOf(r: Record<string, unknown>): string {
  const primary = s(r.denial_reason ?? r.reason ?? r.target);
  if (r.kind !== "auth_failure") return primary || s(r.detail);
  if (!r.client) return [primary, s(r.detail)].filter(Boolean).join(" · ");
  return [
    primary,
    `from ${s(r.client)}`,
    r.fingerprint ? `token ${s(r.fingerprint)}` : "no token sent",
    r.user_agent ? s(r.user_agent) : "",
  ].filter(Boolean).join(" · ");
}

/** Who: the identity and the address it called from, e.g.
 *  "homelab (10.10.110.5)"; for a failed sign-in with no known identity,
 *  just the address. Records from before 1.5.3 carry no address on calls. */
function whoOf(r: Record<string, unknown>): string {
  const who = s(r.identity ?? r.actor);
  const client = s(r.client);
  if (!who) return client;
  return client ? `${who} (${client})` : who;
}

/** What: the tool or action, or the request a failed sign-in made. */
const whatOf = (r: Record<string, unknown>) =>
  r.tool ?? r.action ? s(r.tool ?? r.action) : r.path ? [s(r.method), s(r.path)].filter(Boolean).join(" ") : "";

export function Audit() {
  const [params, setParams] = useSearchParams();
  const identity = params.get("identity") ?? "";
  const tool = params.get("tool") ?? "";
  const outcome = (OUTCOMES as readonly string[]).includes(params.get("outcome") ?? "")
    ? (params.get("outcome") as Outcome)
    : "";

  const query = useInfiniteQuery({
    queryKey: ["audit", identity, tool, outcome],
    queryFn: ({ pageParam }) =>
      apiGet("/audit", { query: { identity, tool, outcome, limit: 100, cursor: pageParam ?? undefined } }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    refetchInterval: usePollInterval(),
  });

  // Infinite scroll: load the next page when the sentinel scrolls into view.
  const sentinel = useRef<HTMLDivElement>(null);
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query;
  useEffect(() => {
    const node = sentinel.current;
    if (!node || typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting) && hasNextPage && !isFetchingNextPage) void fetchNextPage();
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  const entries = query.data?.pages.flatMap((p) => p.entries) ?? [];
  const narrow = useIsNarrow();
  const truncated = query.data?.pages.at(-1)?.window_truncated ?? false;

  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle="The real reason for a denial is recorded here in full, even when the agent only received an opaque answer. Admin changes land here too."
      />
      {/* Keyed on the URL: back/forward or a link from another page changes
          the filter, and the form has to show that, not its stale draft. */}
      <Filters
        key={`${identity}\n${tool}\n${outcome}`}
        identity={identity} tool={tool} outcome={outcome} onApply={(next) => setParams(next)}
      />
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        <Card className={narrow ? undefined : "overflow-x-auto"}>
          {narrow ? (
            // A phone has no room for six columns: one block per entry,
            // the outcome and time on top, the reason underneath.
            <ul className="divide-y divide-border">
              {entries.length === 0 && <li className="px-3 py-6 text-center text-sm text-muted-foreground">No matching entries.</li>}
              {entries.map((r, i) => {
                const detail = detailOf(r);
                return (
                  <li key={i} className="space-y-1 px-3 py-2.5 text-sm">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <span className="font-mono">{formatTime(r.ts, true)}</span>
                      <span>{s(r.kind)}</span>
                      <span className="flex-1" />
                      {r.outcome ? <Badge tone={TONE[s(r.outcome)] ?? "neutral"}>{s(r.outcome)}</Badge> : null}
                    </div>
                    <div className="font-mono wrap-anywhere">
                      {whoOf(r)}
                      {whatOf(r) ? <span className="text-muted-foreground"> → </span> : null}
                      {whatOf(r)}
                    </div>
                    {detail && <div className="font-mono text-xs wrap-anywhere text-muted-foreground">{detail}</div>}
                  </li>
                );
              })}
            </ul>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-muted-foreground">
                <tr>{["Time", "Kind", "Who", "What", "Outcome", "Detail"].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr>
              </thead>
              <tbody>
                {entries.length === 0 && (
                  <tr><td colSpan={6} className="px-3 py-6 text-center text-muted-foreground">No matching entries.</td></tr>
                )}
                {entries.map((r, i) => (
                  <tr key={i} className="border-t border-border align-top">
                    <td className="px-3 py-1.5 font-mono text-xs whitespace-nowrap">{formatTime(r.ts, true)}</td>
                    <td className="px-3 py-1.5">{s(r.kind)}</td>
                    <td className="px-3 py-1.5 font-mono">{whoOf(r)}</td>
                    <td className="px-3 py-1.5 font-mono wrap-break-word">{whatOf(r)}</td>
                    <td className="px-3 py-1.5">
                      {r.outcome ? <Badge tone={TONE[s(r.outcome)] ?? "neutral"}>{s(r.outcome)}</Badge> : null}
                    </td>
                    <td className="min-w-48 px-3 py-1.5 font-mono text-xs wrap-anywhere text-muted-foreground">
                      {detailOf(r)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div ref={sentinel} className="p-3 text-center text-xs text-muted-foreground">
            {isFetchingNextPage ? "Loading more…" : hasNextPage ? (
              <Button size="sm" variant="ghost" onClick={() => void fetchNextPage()}>Load more</Button>
            ) : entries.length > 0 ? "End of the readable window." : null}
          </div>
        </Card>
      )}
      {truncated && (
        <Notice>
          Older entries exist beyond what this page reads (the tail of the current log file). Absence of an
          entry here is not proof that it never happened.
        </Notice>
      )}
    </>
  );
}

function Filters({ identity, tool, outcome, onApply }: {
  identity: string;
  tool: string;
  outcome: Outcome;
  onApply: (next: Record<string, string>) => void;
}) {
  const [draft, setDraft] = useState({ identity, tool, outcome: outcome as string });
  function submit(e: FormEvent) {
    e.preventDefault();
    onApply(Object.fromEntries(Object.entries(draft).filter(([, v]) => v)));
  }
  return (
    <form onSubmit={submit} className="grid grid-cols-2 items-end gap-3 sm:flex sm:flex-wrap">
      <Label text="Identity">
        <Input value={draft.identity} onChange={(e) => setDraft({ ...draft, identity: e.target.value })} />
      </Label>
      <Label text="Tool">
        <Input value={draft.tool} onChange={(e) => setDraft({ ...draft, tool: e.target.value })} />
      </Label>
      <Label text="Outcome">
        <Select value={draft.outcome} onChange={(e) => setDraft({ ...draft, outcome: e.target.value })}>
          {OUTCOMES.map((o) => <option key={o} value={o}>{o || "all"}</option>)}
        </Select>
      </Label>
      <Button type="submit" variant="outline">Filter</Button>
      {(identity || tool || outcome) && (
        <Button variant="ghost" onClick={() => onApply({})}>Clear</Button>
      )}
    </form>
  );
}
