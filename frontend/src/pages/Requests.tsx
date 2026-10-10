// Proposals from an admin-role agent on /admin/mcp, decided only here by a
// human (FR-2.8): tool, grant and role changes on the Change tab, Tier 1
// toolkit proposals on the Toolkit tab. Everything an agent wrote is
// rendered as text.
import { useState } from "react";
import { useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
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
import { Row } from "./Identities";

type Pending = Schemas["PendingItem"];
type Proposal = Schemas["ToolkitProposalOut"];

const POLL_MS = 15_000;
const ARCHIVE_PAGE = 25;
const DONE_CHANGE = new Set(["approved", "rejected", "stale"]);
const DONE_TOOLKIT = new Set(["deployed", "rejected"]);
const INVALIDATES = [["requests"], ["overview"], ["tools"], ["identities"], ["credentials"], ["toolkits"]];

const STATUS_TONE: Record<string, Tone> = {
  pending: "warn", approved: "ok", deployed: "ok", rejected: "neutral", stale: "deny",
};

function usePending() {
  return useQuery({
    queryKey: ["requests", "pending"],
    queryFn: () => apiGet("/requests/pending"),
    refetchInterval: POLL_MS,
  });
}

function useToolkitProposals() {
  return useQuery({
    queryKey: ["requests", "toolkits"],
    queryFn: () => apiGet("/requests/toolkits"),
    refetchInterval: POLL_MS,
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

function ChangeTab({ items }: { items: Pending[] }) {
  const canWrite = useCanWrite();
  const live = items.filter((i) => !DONE_CHANGE.has(i.status));
  const archived = items.filter((i) => DONE_CHANGE.has(i.status));
  const batchable = live.filter((i) => i.status === "pending" && i.action !== "cred_propose");
  if (!items.length) {
    return (
      <Notice>
        No proposals yet. This fills up when an admin-role agent on /admin/mcp proposes enabling,
        updating or deleting a tool, setting a grant, changing a role, or a new credential.
      </Notice>
    );
  }
  return (
    <>
      {canWrite && batchable.length >= 2 && <ApproveAll items={batchable} />}
      {live.length === 0 ? <p className="text-sm text-muted-foreground">Nothing pending.</p> : (
        [...live].reverse().map((item) => <PendingCard key={item.id} item={item} canDecide={canWrite} />)
      )}
      <Archive items={archived} render={(item) => <PendingCard key={item.id} item={item} canDecide={false} />} />
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
          <code>{t.id}</code>
          <span className="text-muted-foreground">
            {t.state === "missing" ? "no such tool in the catalog" : `${t.title} (${t.category})`}
          </span>
        </div>
      ))}
    </div>
  );
}

function PendingCard({ item, canDecide }: { item: Pending; canDecide: boolean }) {
  const [mode, setMode] = useState<"" | "reject" | "fill">("");
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
  return (
    <Card>
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
              <Button size="sm" disabled={approve.isPending} onClick={() => approve.mutate(undefined)}>
                <Check className="size-3.5" /> Approve
              </Button>
            )}
            <Button size="sm" variant="outline" onClick={() => setMode("reject")}><X className="size-3.5" /> Reject</Button>
          </div>
        )}
        {open && mode === "reject" && (
          <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); reject.mutate(undefined); }}>
            <Label text="Reason (optional)">
              <Input value={reason} maxLength={240} onChange={(e) => setReason(e.target.value)} />
            </Label>
            <Button size="sm" variant="destructive" type="submit" disabled={reject.isPending}>Reject</Button>
            <Button size="sm" variant="ghost" type="button" onClick={() => setMode("")}>Cancel</Button>
          </form>
        )}
        {open && mode === "fill" && (
          <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); fill.mutate(undefined); }}>
            <p className="text-xs text-muted-foreground">
              The agent proposed the name and kind only. The value is typed here, encrypted, and never shown again.
            </p>
            <Label text="Credential value">
              <Input type="password" autoComplete="off" required value={value} onChange={(e) => setValue(e.target.value)} />
            </Label>
            <div className="flex gap-2">
              <Button size="sm" type="submit" disabled={fill.isPending}>Approve with this value</Button>
              <Button size="sm" variant="ghost" type="button" onClick={() => setMode("")}>Cancel</Button>
            </div>
          </form>
        )}
        <WriteError error={approve.error ?? reject.error ?? fill.error} />
      </CardBody>
    </Card>
  );
}

function ApproveAll({ items }: { items: Pending[] }) {
  const [asking, setAsking] = useState(false);
  const run = useWrite(
    () => apiSend<Schemas["ApproveAllResult"]>("POST", "/requests/pending/approve-all", {
      // Exactly what is listed here; anything filed meanwhile stays pending.
      body: { ids: items.map((i) => i.id) },
    }),
    INVALIDATES,
    () => setAsking(false),
  );
  return (
    <Card>
      <CardBody className="space-y-2 text-sm">
        {!asking ? (
          <Button size="sm" onClick={() => { run.reset(); setAsking(true); }}>
            <Check className="size-3.5" /> Approve all ({items.length})
          </Button>
        ) : (
          <>
            <p className="font-medium">Approve all {items.length} pending proposals?</p>
            <p className="text-xs text-muted-foreground">
              Each is applied on its own, oldest first. A refusal (a stale proposal, say) does not stop the rest.
              Credential proposals are not included; each needs its value.
            </p>
            <ul className="space-y-1">
              {items.map((i) => (
                <li key={i.id} className="flex gap-2"><code className="text-xs">{i.action}</code><span>{i.review.headline}</span></li>
              ))}
            </ul>
            <div className="flex gap-2">
              <Button size="sm" disabled={run.isPending} onClick={() => run.mutate(undefined)}>Approve all {items.length}</Button>
              <Button size="sm" variant="ghost" onClick={() => setAsking(false)}>Cancel</Button>
            </div>
          </>
        )}
        {run.data && run.data.refused.length > 0 && (
          <Notice tone="bad">
            <strong>Applied {run.data.applied}. Refused {run.data.refused.length}.</strong>
            <ul>
              {run.data.refused.map((r) => <li key={r.id}><code>{r.action}</code> {r.id}: {r.reason}</li>)}
            </ul>
          </Notice>
        )}
        <WriteError error={run.error} />
      </CardBody>
    </Card>
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
        Adding a toolkit, changing an existing one's executor, binaries, denied_args or run_as, or binding one
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
    return {
      text: `${head}Deploying merges the fields below into toolkit ${item.name} and reloads it at once; only executor, binaries, denied_args and run_as can change.${runAs}`,
      ack: "I understand this immediately changes what this toolkit can reach.",
      label: "Approve and deploy update",
    };
  }
  return {
    text: `${head}Deploying writes the toolkit below into toolkits.yaml and reloads it at once: every binary, path root and destination it lists becomes reachable, with no further review.`,
    ack: "I understand this immediately expands what this deployment can reach.",
    label: "Approve and deploy",
  };
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
  return (
    <Card>
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
              <Button size="sm" variant="destructive" type="submit" disabled={!ack || deploy.isPending}>{warning.label}</Button>
              <Button size="sm" variant="ghost" type="button" onClick={() => { setMode(""); setAck(false); }}>Cancel</Button>
            </div>
          </form>
        )}
        {open && mode === "reject" && (
          <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); reject.mutate(undefined); }}>
            <Label text="Reason (optional)">
              <Input value={reason} maxLength={240} onChange={(e) => setReason(e.target.value)} />
            </Label>
            <Button size="sm" variant="destructive" type="submit" disabled={reject.isPending}>Reject</Button>
            <Button size="sm" variant="ghost" type="button" onClick={() => setMode("")}>Cancel</Button>
          </form>
        )}
        <WriteError error={deploy.error ?? reject.error} />
      </CardBody>
    </Card>
  );
}
