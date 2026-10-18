// Proposals from an admin-role agent on /admin/mcp, decided only here by a
// human (FR-2.8): tool, grant and role changes on the Change tab, Tier 1
// toolkit proposals on the Toolkit tab. Everything an agent wrote is
// rendered as text.
import { useState } from "react";
import { useSearchParams } from "react-router";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Check, X } from "lucide-react";
import { apiGet, apiSend, type Schemas } from "@/api/client";
import { useCanWrite } from "@/auth";
import { useWrite, WriteError } from "@/components/forms";
import { PageHeader } from "@/components/Layout";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { CodeBlock } from "@/components/ui/copy";
import { Input, Label } from "@/components/ui/input";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { cn, formatTime } from "@/lib/utils";
import { usePollInterval } from "@/live";
import { Row } from "./Identities";

type Pending = Schemas["PendingItem"];
type Proposal = Schemas["ToolkitProposalOut"];

const ARCHIVE_PAGE = 25;
const DONE_CHANGE = new Set(["approved", "rejected", "stale"]);
const DONE_TOOLKIT = new Set(["deployed", "rejected", "withdrawn"]);
const INVALIDATES = [["requests"], ["overview"], ["tools"], ["identities"], ["credentials"], ["toolkits"]];

const STATUS_TONE: Record<string, Tone> = {
  pending: "warn", approved: "ok", deployed: "ok", rejected: "neutral", withdrawn: "neutral", stale: "deny",
};

function usePending() {
  return useQuery({
    queryKey: ["requests", "pending"],
    // Open items only; decided ones come a page at a time from /requests/decided.
    queryFn: () => apiGet("/requests/pending", { query: { status: "pending" } }),
    refetchInterval: usePollInterval(),
  });
}

function useToolkitProposals() {
  return useQuery({
    queryKey: ["requests", "toolkits"],
    queryFn: () => apiGet("/requests/toolkits"),
    refetchInterval: usePollInterval(),
  });
}

/** Open proposals across both tabs, for the sidebar badge. */
export function useOpenRequestCount(): number {
  const change = usePending();
  const toolkit = useToolkitProposals();
  return (change.data?.filter((i) => i.status === "pending").length ?? 0)
    + (toolkit.data?.filter((i) => i.status === "pending").length ?? 0);
}

export function Requests() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "toolkit" ? "toolkit" : "change";
  const change = usePending();
  const toolkit = useToolkitProposals();
  const changeOpen = change.data?.filter((i) => i.status === "pending").length ?? 0;
  const toolkitOpen = toolkit.data?.filter((i) => i.status === "pending").length ?? 0;
  return (
    <>
      <PageHeader
        title="Requests"
        subtitle="Proposals from an admin-role agent on /admin/mcp. Only a human can approve or reject one; there is no path from /admin/mcp to this decision."
      />
      <div role="tablist" className="flex gap-1 border-b border-border">
        {([["change", "Change", changeOpen], ["toolkit", "Toolkit", toolkitOpen]] as const).map(([key, label, n]) => (
          <button
            key={key} role="tab" type="button" aria-selected={tab === key}
            onClick={() => setParams(key === "change" ? {} : { tab: key })}
            className={cn(
              "-mb-px flex items-center gap-2 border-b-2 px-3 py-2 text-sm",
              tab === key ? "border-primary font-medium text-primary" : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {label}
            {n > 0 && <Badge tone="warn">{n}</Badge>}
          </button>
        ))}
      </div>
      {tab === "change" ? (
        change.isPending ? <Loading /> : change.isError ? <QueryError error={change.error} /> : <ChangeTab items={change.data} />
      ) : toolkit.isPending ? <Loading /> : toolkit.isError ? <QueryError error={toolkit.error} /> : (
        <ToolkitTab items={toolkit.data} />
      )}
    </>
  );
}

function Meta({ actor, at }: { actor: string; at: string }) {
  return <span className="text-xs text-muted-foreground">{actor} · {formatTime(at, true)}</span>;
}

function Decision({ item }: { item: Pending | Proposal }) {
  if (item.status === "pending") return null;
  return (
    <Row label="Decision">
      {item.decided_by ?? ""} · {formatTime(item.decided_at, true)}
      {item.reason ? ` · ${item.reason}` : ""}
    </Row>
  );
}

function Archive<T extends { id: string }>({ items, render }: { items: T[]; render: (item: T) => React.ReactNode }) {
  const [shown, setShown] = useState(0);
  if (!items.length) return null;
  const newest = [...items].reverse();
  return (
    <section className="space-y-2">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold">Archive ({items.length})</h2>
        {shown === 0 ? (
          <Button size="sm" variant="outline" onClick={() => setShown(ARCHIVE_PAGE)}>Show</Button>
        ) : (
          <Button size="sm" variant="ghost" onClick={() => setShown(0)}>Hide</Button>
        )}
      </div>
      {newest.slice(0, shown).map(render)}
      {shown > 0 && shown < newest.length && (
        <Button size="sm" variant="outline" onClick={() => setShown(shown + ARCHIVE_PAGE)}>Older</Button>
      )}
    </section>
  );
}

// -- Change tab ---------------------------------------------------------------------------

function useDecided() {
  return useInfiniteQuery({
    queryKey: ["requests", "decided"],
    queryFn: ({ pageParam }) =>
      apiGet("/requests/decided", { query: { limit: ARCHIVE_PAGE, cursor: pageParam ?? undefined } }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
}

function ChangeArchive({ decided }: { decided: ReturnType<typeof useDecided> }) {
  const [open, setOpen] = useState(false);
  const total = decided.data?.pages[0]?.total ?? 0;
  if (!total) return null;
  const entries = decided.data?.pages.flatMap((p) => p.entries) ?? [];
  return (
    <section className="space-y-2">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold">Archive ({total})</h2>
        <Button size="sm" variant={open ? "ghost" : "outline"} onClick={() => setOpen(!open)}>
          {open ? "Hide" : "Show"}
        </Button>
      </div>
      {open && entries.map((item) => <PendingCard key={item.id} item={item} canDecide={false} />)}
      {open && decided.hasNextPage && (
        <Button
          size="sm" variant="outline" disabled={decided.isFetchingNextPage}
          onClick={() => void decided.fetchNextPage()}
        >
          Older
        </Button>
      )}
    </section>
  );
}

function ChangeTab({ items }: { items: Pending[] }) {
  const canWrite = useCanWrite();
  const decided = useDecided();
  const live = items.filter((i) => !DONE_CHANGE.has(i.status));
  const open = live.filter((i) => i.status === "pending");
  // A credential proposal needs a typed value, and a risky change needs its
  // own second look, so neither is approved in a batch; rejecting needs
  // nothing, so Reject all takes them too.
  const batchable = open.filter((i) => i.action !== "cred_propose" && approvalRisks(i).length === 0);
  if (decided.isError) return <QueryError error={decided.error} />;
  if (decided.isPending) return <Loading />;
  if (!live.length && !decided.data.pages[0]?.total) {
    return (
      <Notice>
        No proposals yet. This fills up when an admin-role agent on /admin/mcp proposes enabling,
        updating or deleting a tool, setting a grant, changing a role, or a new credential.
      </Notice>
    );
  }
  return (
    <>
      {canWrite && open.length >= 2 && <DecideAll approvable={batchable} rejectable={open} />}
      {live.length === 0 ? <p className="text-sm text-muted-foreground">Nothing pending.</p> : (
        [...live].reverse().map((item) => <PendingCard key={item.id} item={item} canDecide={canWrite} />)
      )}
      <ChangeArchive decided={decided} />
    </>
  );
}

function Review({ review }: { review: Pending["review"] }) {
  return (
    <div className="space-y-1">
      <p>{review.headline}</p>
      {review.tools.map((t) => (
        <div key={`${t.marker}${t.id}`} className="flex flex-wrap items-center gap-1.5 text-xs">
          {t.marker && <Badge tone={t.marker === "+" ? "ok" : "deny"}>{t.marker === "+" ? "+" : "−"}</Badge>}
          <Badge tone={t.state === "enabled" ? "ok" : t.state === "disabled" ? "warn" : "deny"}>{t.state}</Badge>
          <code className="min-w-0 wrap-anywhere">{t.id}</code>
          <span className="text-muted-foreground">
            {t.state === "missing" ? "no such tool in the catalog" : `${t.title} (${t.category})`}
          </span>
        </div>
      ))}
    </div>
  );
}

/** Why approving this needs a second look, in the reviewer's terms; empty
 *  for a routine change. A grant_set replaces the identity's whole list,
 *  so an agent asking to add one tool can also strip every other grant. */
export function approvalRisks(item: Pending): string[] {
  const risks: string[] = [];
  const identity = String(item.payload.identity_id ?? "");
  if (item.action === "grant_set") {
    const removed = item.review.tools.filter((t) => t.marker === "-").length;
    const missing = item.review.tools.filter((t) => t.marker !== "-" && t.state === "missing").length;
    if (removed) {
      risks.push(`It takes away ${removed} existing grant${removed === 1 ? "" : "s"} from ${identity}: a grant proposal replaces the whole list.`);
    }
    if (missing) {
      risks.push(`It grants ${missing} tool${missing === 1 ? "" : "s"} that ${missing === 1 ? "is" : "are"} not in the catalog.`);
    }
  }
  if (item.action === "role_set") {
    risks.push(item.payload.role === "admin"
      ? `It makes ${identity} an admin, the most privileged role.`
      : `It changes the role of ${identity}.`);
  }
  if (item.action === "tool_delete") {
    risks.push(`It deletes tool ${String(item.payload.id ?? "")}: every identity granted it loses it.`);
  }
  return risks;
}

function PendingCard({ item, canDecide }: { item: Pending; canDecide: boolean }) {
  const [mode, setMode] = useState<"" | "reject" | "fill" | "confirm">("");
  const [reason, setReason] = useState("");
  const [value, setValue] = useState("");
  const base = `/requests/pending/${encodeURIComponent(item.id)}`;
  const approve = useWrite(() => apiSend("POST", `${base}/approve`), INVALIDATES);
  const reject = useWrite(() => apiSend("POST", `${base}/reject`, { body: { reason } }), INVALIDATES);
  const fill = useWrite(
    () => apiSend("POST", `${base}/credential`, { body: { value } }),
    INVALIDATES, () => setValue(""),
  );
  const open = item.status === "pending" && canDecide;
  const working = approve.isPending || reject.isPending || fill.isPending;
  const risks = approvalRisks(item);
  return (
    <Card aria-busy={working || undefined}>
      <CardHeader
        title={<span className="font-mono">{item.action}</span>}
        actions={
          <span className="flex flex-wrap items-center gap-2">
            <Meta actor={item.actor} at={item.created_at} />
            <Badge tone={STATUS_TONE[item.status] ?? "neutral"}>{item.status}</Badge>
          </span>
        }
      />
      <CardBody className="space-y-2 text-sm">
        <Row label="Change"><Review review={item.review} /></Row>
        {item.review.stale && <Row label="Why">{item.review.stale}</Row>}
        <Decision item={item} />
        {open && mode === "" && (
          <div className="flex gap-1 pt-1">
            {item.action === "cred_propose" ? (
              <Button size="sm" onClick={() => setMode("fill")}><Check className="size-3.5" /> Approve</Button>
            ) : (
              <Button
                size="sm" busy={approve.isPending} busyLabel="Approving…"
                onClick={() => (risks.length ? setMode("confirm") : approve.mutate(undefined))}
              >
                <Check className="size-3.5" /> Approve
              </Button>
            )}
            <Button size="sm" variant="outline" disabled={working} onClick={() => setMode("reject")}><X className="size-3.5" /> Reject</Button>
          </div>
        )}
        {open && mode === "confirm" && (
          <div className="space-y-2">
            <Notice tone="bad">
              <strong>Check this before approving.</strong>
              <ul className="list-disc space-y-1 pl-4">
                {risks.map((r) => <li key={r}>{r}</li>)}
              </ul>
            </Notice>
            <div className="flex gap-2">
              <Button size="sm" variant="destructive" busy={approve.isPending} busyLabel="Approving…" onClick={() => approve.mutate(undefined)}>
                Approve anyway
              </Button>
              <Button size="sm" variant="ghost" disabled={working} onClick={() => setMode("")}>Cancel</Button>
            </div>
          </div>
        )}
        {open && mode === "reject" && (
          <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); reject.mutate(undefined); }}>
            <Label text="Reason (optional)">
              <Input autoFocus value={reason} maxLength={240} onChange={(e) => setReason(e.target.value)} />
            </Label>
            <Button size="sm" variant="destructive" type="submit" busy={reject.isPending} busyLabel="Rejecting…">Reject</Button>
            <Button size="sm" variant="ghost" type="button" disabled={working} onClick={() => setMode("")}>Cancel</Button>
          </form>
        )}
        {open && mode === "fill" && (
          <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); fill.mutate(undefined); }}>
            <p className="text-xs text-muted-foreground">
              The agent proposed the name and kind only. The value is typed here, encrypted, and never shown again.
            </p>
            <Label text="Credential value">
              <Input autoFocus type="password" autoComplete="off" required value={value} onChange={(e) => setValue(e.target.value)} />
            </Label>
            <div className="flex gap-2">
              <Button size="sm" type="submit" busy={fill.isPending} busyLabel="Approving…">Approve with this value</Button>
              <Button size="sm" variant="ghost" type="button" disabled={working} onClick={() => setMode("")}>Cancel</Button>
            </div>
          </form>
        )}
        <Working active={working} />
        <WriteError error={approve.error ?? reject.error ?? fill.error} />
      </CardBody>
    </Card>
  );
}

function DecideAll({ approvable, rejectable }: { approvable: Pending[]; rejectable: Pending[] }) {
  const [asking, setAsking] = useState<"" | "approve" | "reject">("");
  // The list as it stood when the question opened. A proposal that arrives
  // over the live stream while it is open must not join a batch nobody saw.
  const [listed, setListed] = useState<Pending[]>([]);
  const [reason, setReason] = useState("");
  const approve = useWrite(
    () => apiSend<Schemas["ApproveAllResult"]>("POST", "/requests/pending/approve-all", {
      // Exactly what is listed here; anything filed meanwhile stays pending.
      body: { ids: listed.map((i) => i.id) },
    }),
    INVALIDATES,
    () => setAsking(""),
  );
  const reject = useWrite(
    () => apiSend<Schemas["RejectAllResult"]>("POST", "/requests/pending/reject-all", {
      body: { ids: listed.map((i) => i.id), reason },
    }),
    INVALIDATES,
    () => { setAsking(""); setReason(""); },
  );
  const working = approve.isPending || reject.isPending;
  const start = (mode: "approve" | "reject") => {
    approve.reset(); reject.reset();
    setListed(mode === "approve" ? approvable : rejectable);
    setAsking(mode);
  };
  const items = listed;
  return (
    <Card aria-busy={working || undefined}>
      <CardBody className="space-y-2 text-sm">
        {asking === "" ? (
          <div className="flex flex-wrap gap-1">
            {approvable.length >= 2 && (
              <Button size="sm" onClick={() => start("approve")}>
                <Check className="size-3.5" /> Approve all ({approvable.length})
              </Button>
            )}
            <Button size="sm" variant="outline" onClick={() => start("reject")}>
              <X className="size-3.5" /> Reject all ({rejectable.length})
            </Button>
          </div>
        ) : (
          <>
            <p className="font-medium">
              {asking === "approve" ? "Approve" : "Reject"} all {items.length} pending proposals?
            </p>
            <p className="text-xs text-muted-foreground">
              {asking === "approve"
                ? "Each is applied on its own, oldest first. A refusal (a stale proposal, say) does not stop the rest. Credential proposals and changes that need a second look (removed grants, unknown tools, role changes, deletions) are not included; approve those one at a time. A proposal filed after you opened this stays pending."
                : "Each is rejected with the same reason, credential proposals included. Nothing is applied. A proposal filed after you opened this stays pending."}
            </p>
            <ul className="space-y-1">
              {items.map((i) => (
                <li key={i.id} className="flex gap-2"><code className="text-xs">{i.action}</code><span>{i.review.headline}</span></li>
              ))}
            </ul>
            {asking === "approve" ? (
              <div className="flex gap-2">
                <Button size="sm" busy={approve.isPending} busyLabel={`Approving ${items.length}…`} onClick={() => approve.mutate(undefined)}>
                  Approve all {items.length}
                </Button>
                <Button size="sm" variant="ghost" disabled={working} onClick={() => setAsking("")}>Cancel</Button>
              </div>
            ) : (
              <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); reject.mutate(undefined); }}>
                <Label text="Reason (optional)">
                  <Input autoFocus value={reason} maxLength={240} onChange={(e) => setReason(e.target.value)} />
                </Label>
                <Button size="sm" variant="destructive" type="submit" busy={reject.isPending} busyLabel={`Rejecting ${items.length}…`}>
                  Reject all {items.length}
                </Button>
                <Button size="sm" variant="ghost" type="button" disabled={working} onClick={() => setAsking("")}>Cancel</Button>
              </form>
            )}
          </>
        )}
        <Working active={working} />
        {approve.data && approve.data.refused.length > 0 && <BatchRefusals verb="Applied" done={approve.data.applied} refused={approve.data.refused} />}
        {reject.data && reject.data.refused.length > 0 && <BatchRefusals verb="Rejected" done={reject.data.rejected} refused={reject.data.refused} />}
        <WriteError error={approve.error ?? reject.error} />
      </CardBody>
    </Card>
  );
}

function BatchRefusals({ verb, done, refused }: { verb: string; done: number; refused: Schemas["Refusal"][] }) {
  return (
    <Notice tone="bad">
      <strong>{verb} {done}. Refused {refused.length}.</strong>
      <ul>
        {refused.map((r) => <li key={r.id}><code>{r.action}</code> {r.id}: {r.reason}</li>)}
      </ul>
    </Notice>
  );
}

// -- Toolkit tab -------------------------------------------------------------------------

function ToolkitTab({ items }: { items: Proposal[] }) {
  const canWrite = useCanWrite();
  const live = items.filter((i) => !DONE_TOOLKIT.has(i.status));
  const archived = items.filter((i) => DONE_TOOLKIT.has(i.status));
  return (
    <>
      <Notice>
        Adding a toolkit, changing an existing one's executor, binaries, denied_args, run_as, network targets, methods, path prefixes, path roots or limits, or binding one
        to a credential normally needs a redeploy: Tier 1 is immutable at runtime. A proposal here is the one way
        around that, and only a human can make it take effect.
      </Notice>
      {!items.length ? (
        <Notice>No proposals yet. This fills up when an admin-role agent calls admin.toolkit_propose, admin.toolkit_update or admin.credential_bind.</Notice>
      ) : (
        <>
          {live.length === 0 ? <p className="text-sm text-muted-foreground">Nothing pending.</p> : (
            [...live].reverse().map((item) => <ProposalCard key={item.id} item={item} canDecide={canWrite} />)
          )}
          <Archive items={archived} render={(item) => <ProposalCard key={item.id} item={item} canDecide={false} />} />
        </>
      )}
    </>
  );
}

const NETWORK_FIELDS = ["allowed_hosts", "allowed_cidrs"] as const;

/** What every field an update proposal changes holds today, for the card's
 * "Currently" row: the "before" to the "Proposed changes" row's "after". */
function currentValues(item: Proposal): string {
  const current = item.current as Record<string, unknown> | null | undefined;
  if (!current) return "";
  const lines = Object.keys(item.spec).map((field) => {
    const value = current[field];
    if (Array.isArray(value)) return `${field}: ${value.length ? value.join(", ") : "(none)"}`;
    return `${field}: ${value === null || value === undefined ? "(none)" : String(value)}`;
  });
  return lines.join("\n");
}

/** The proposed path_roots against today's, one root per line: "+" added,
 *  "−" removed, two spaces kept. Empty when the proposal does not touch
 *  path_roots or the toolkit is gone. Only meaningful while pending: once
 *  deployed, "today's" is the proposed list. */
export function pathRootsDiff(item: Proposal): string {
  const proposed = item.spec.path_roots;
  if (item.kind !== "update" || !Array.isArray(proposed) || !item.current) return "";
  const before = item.current.path_roots;
  const after = proposed.map(String);
  const lines = [
    ...before.map((r) => `${after.includes(r) ? " " : "−"} ${r}`),
    ...after.filter((r) => !before.includes(r)).map((r) => `+ ${r}`),
  ];
  return lines.length ? lines.join("\n") : "(no roots before or after)";
}

const KIND_TONE: Record<string, Tone> = { delete: "deny", bind: "accent", update: "accent", create: "accent" };

function bindTarget(item: Proposal): string {
  const value = item.spec.credential;
  return typeof value === "string" ? value : "";
}

/** Why deploying is not a routine click, in the reviewer's terms. */
function deployWarning(item: Proposal): { text: string; ack: string; label: string } {
  const now = item.current?.credential ?? null;
  const head = "This changes Tier 1, which normally takes a human editing toolkits.yaml and redeploying. ";
  if (item.kind === "delete") {
    return {
      text: `${head}Deploying removes toolkit ${item.name} and reloads Tier 1 at once: every tool on it stops working, with no further review.`,
      ack: "I understand this immediately removes this toolkit and breaks every tool still on it.",
      label: "Approve and deploy delete",
    };
  }
  if (item.kind === "bind") {
    const target = bindTarget(item);
    const redirect = now && now !== target
      ? ` This redirects an existing binding: ${item.name} uses ${now} today, and whatever ${target} authenticates as becomes who this toolkit is to the remote side.`
      : "";
    return {
      text: `${head}Deploying writes credential: ${target} under toolkit ${item.name} and reloads it at once (FR-10.4). Nothing else about the toolkit changes.${redirect}`,
      ack: "I understand this immediately changes which credential this toolkit authenticates with.",
      label: "Approve and deploy binding",
    };
  }
  if (item.kind === "update") {
    const runAs = "run_as" in item.spec
      ? ` This proposal changes run_as: file operations on this toolkit would run as ${String(item.spec.run_as)}, within its existing path_roots, and fail where the container cannot change user.`
      : "";
    const network = NETWORK_FIELDS.filter((f) => f in item.spec);
    const reach = network.length
      ? ` This proposal changes where the toolkit may connect (${network.join(", ")}): the targets below become reachable as soon as you deploy. A hostname never reaches a private or loopback address.`
      : "";
    const roots = Array.isArray(item.spec.path_roots)
      ? ` This proposal changes path_roots: tools on this toolkit may read, write or upload files under every root marked + as soon as you deploy.`
      : "";
    return {
      text: `${head}Deploying merges the fields below into toolkit ${item.name} and reloads it at once; protected_resources cannot change this way.${runAs}${reach}${roots}${broad(item)}`,
      ack: "I understand this immediately changes what this toolkit can reach.",
      label: "Approve and deploy update",
    };
  }
  return {
    text: `${head}Deploying writes the toolkit below into toolkits.yaml and reloads it at once: every binary, path root and destination it lists becomes reachable, with no further review.${broad(item)}`,
    ack: "I understand this immediately expands what this deployment can reach.",
    label: "Approve and deploy",
  };
}

function broad(item: Proposal): string {
  return item.confirm_broad_cidrs
    ? " The proposer confirmed an allowed_cidrs entry wider than /16 (IPv4) or /48 (IPv6): check that this width is really needed."
    : "";
}

function ProposalCard({ item, canDecide }: { item: Proposal; canDecide: boolean }) {
  const [mode, setMode] = useState<"" | "deploy" | "reject">("");
  const [ack, setAck] = useState(false);
  const [reason, setReason] = useState("");
  const base = `/requests/toolkits/${encodeURIComponent(item.id)}`;
  const deploy = useWrite(() => apiSend("POST", `${base}/deploy`, { body: { confirm: true } }), INVALIDATES);
  const reject = useWrite(() => apiSend("POST", `${base}/reject`, { body: { reason } }), INVALIDATES);
  const open = item.status === "pending" && canDecide;
  const current = item.current?.credential ?? null;
  const warning = deployWarning(item);
  const working = deploy.isPending || reject.isPending;
  return (
    <Card aria-busy={working || undefined}>
      <CardHeader
        title={<span className="font-mono">{item.name}</span>}
        actions={
          <span className="flex flex-wrap items-center gap-2">
            <Meta actor={item.actor} at={item.created_at} />
            <Badge tone={KIND_TONE[item.kind] ?? "accent"}>{item.kind}</Badge>
            <Badge tone={STATUS_TONE[item.status] ?? "neutral"}>{item.status}</Badge>
          </span>
        }
      />
      <CardBody className="space-y-2 text-sm">
        {item.kind === "delete" && <Row label="Change">Removes this toolkit.</Row>}
        {item.kind === "bind" && (
          <>
            <Row label="Credential"><code>{bindTarget(item)}</code> (a name; the value stays in the credential store)</Row>
            <Row label="Replaces">
              {current && current !== bindTarget(item) ? <><code>{current}</code>, the binding this toolkit has now</>
                : current ? "Nothing: this is already its binding, deploying changes nothing."
                : "Nothing: this toolkit has no credential today."}
            </Row>
          </>
        )}
        {item.confirm_broad_cidrs && (
          <Notice tone="bad">Contains an allowed_cidrs entry wider than /16 (IPv4) or /48 (IPv6), confirmed by the proposer.</Notice>
        )}
        {item.status === "pending" && pathRootsDiff(item) && (
          <Row label="Path roots"><CodeBlock text={pathRootsDiff(item)} /></Row>
        )}
        {item.kind === "update" && currentValues(item) && (
          <Row label="Currently"><CodeBlock text={currentValues(item)} /></Row>
        )}
        {item.spec_yaml && (
          <Row label={item.kind === "update" ? "Proposed changes" : "Proposed toolkit"}>
            <CodeBlock text={item.spec_yaml} />
          </Row>
        )}
        <Decision item={item} />
        {open && mode === "" && (
          <div className="flex gap-1 pt-1">
            <Button size="sm" variant="destructive" onClick={() => setMode("deploy")}>
              <AlertTriangle className="size-3.5" /> Approve and deploy
            </Button>
            <Button size="sm" variant="outline" onClick={() => setMode("reject")}><X className="size-3.5" /> Reject</Button>
          </div>
        )}
        {open && mode === "deploy" && (
          <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); deploy.mutate(undefined); }}>
            <Notice tone="bad">{warning.text}</Notice>
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" checked={ack} onChange={(e) => setAck(e.target.checked)} required />
              {warning.ack}
            </label>
            <div className="flex gap-2">
              <Button size="sm" variant="destructive" type="submit" disabled={!ack} busy={deploy.isPending} busyLabel="Deploying…">{warning.label}</Button>
              <Button size="sm" variant="ghost" type="button" disabled={working} onClick={() => { setMode(""); setAck(false); }}>Cancel</Button>
            </div>
          </form>
        )}
        {open && mode === "reject" && (
          <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); reject.mutate(undefined); }}>
            <Label text="Reason (optional)">
              <Input autoFocus value={reason} maxLength={240} onChange={(e) => setReason(e.target.value)} />
            </Label>
            <Button size="sm" variant="destructive" type="submit" busy={reject.isPending} busyLabel="Rejecting…">Reject</Button>
            <Button size="sm" variant="ghost" type="button" disabled={working} onClick={() => setMode("")}>Cancel</Button>
          </form>
        )}
        <Working active={working} />
        <WriteError error={deploy.error ?? reject.error} />
      </CardBody>
    </Card>
  );
}

/** Said while a decision is in flight. Applying one reloads the store and
 *  refreshes this page, which takes a few seconds; without a word here the
 *  greyed-out buttons read as a hung page. */
function Working({ active }: { active: boolean }) {
  if (!active) return null;
  return (
    <p role="status" className="text-xs text-muted-foreground">
      Applying the decision and refreshing the console. This can take a few seconds.
    </p>
  );
}
