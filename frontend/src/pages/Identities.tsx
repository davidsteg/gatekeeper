import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { apiGet, apiSend, etagFor, type Schemas } from "@/api/client";
import { useAuth, useCanWrite } from "@/auth";
import { ConfirmButton, OneTimeSecret, Textarea, useWrite, WriteError } from "@/components/forms";
import { PageHeader } from "@/components/Layout";
import { Badge, Pills } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Loading, Notice, QueryError } from "@/components/ui/notice";

type Identity = Schemas["IdentityOut"];
type TokenIssued = Schemas["TokenIssued"];

const CONSOLE = {
  access: { tone: "ok", text: "console access" },
  no_password: { tone: "deny", text: "no console password" },
  api_only: { tone: "neutral", text: "api only" },
} as const;

const ROLES = ["agent", "viewer", "admin"] as const;
const LIST = "/identities";
const INVALIDATES = [["identities"], ["overview"], ["tools"]];

export function Identities() {
  const canWrite = useCanWrite();
  const query = useQuery({ queryKey: ["identities"], queryFn: () => apiGet("/identities") });
  const [editing, setEditing] = useState<string | null>(null);
  const [issued, setIssued] = useState<TokenIssued | null>(null);
  return (
    <>
      <PageHeader
        title="Identities"
        subtitle="Rights attach to individual tool IDs, never to a whole toolkit. API tokens and console passwords are stored as scrypt hashes and are never shown."
        actions={canWrite && editing !== "" && (
          <Button size="sm" onClick={() => { setIssued(null); setEditing(""); }}>
            <Plus className="size-3.5" /> New identity
          </Button>
        )}
      />
      {issued && <OneTimeSecret title={`API token for ${issued.identity}`} value={issued.token} />}
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        <>
          {editing === "" && (
            <IdentityEditor
              onDone={(token) => { setEditing(null); if (token) setIssued(token); }}
              onReload={() => query.refetch()}
            />
          )}
          {query.data.map((ident) =>
            editing === ident.id ? (
              <IdentityEditor
                key={ident.id} current={ident}
                onDone={() => setEditing(null)} onReload={() => query.refetch()}
              />
            ) : (
              <IdentityCard
                key={ident.id} ident={ident} canWrite={canWrite}
                onEdit={() => { setIssued(null); setEditing(ident.id); }}
              />
            ),
          )}
        </>
      )}
    </>
  );
}

function IdentityCard({ ident, canWrite, onEdit }: {
  ident: Identity;
  canWrite: boolean;
  onEdit: () => void;
}) {
  const { session } = useAuth();
  // A rotated token is shown in this card, where the button was clicked --
  // at the top of a long list it went unseen.
  const [rotated, setRotated] = useState<string | null>(null);
  const console = CONSOLE[ident.console];
  const self = `${LIST}/${encodeURIComponent(ident.id)}`;
  const rotate = useWrite(
    () => apiSend<TokenIssued>("POST", `${self}/token`, { ifMatchOf: LIST }),
    INVALIDATES, (issued) => setRotated(issued.token),
  );
  const remove = useWrite(
    () => apiSend("DELETE", self, { ifMatchOf: LIST }),
    // Deleting yourself ends your session: re-checking it sends you to sign-in.
    ident.id === session?.identity ? [...INVALIDATES, ["session"]] : INVALIDATES,
  );
  return (
    <Card>
      <CardHeader
        title={<span className="font-mono">{ident.id}</span>}
        actions={
          <span className="flex gap-1">
            <Badge tone={ident.role === "admin" ? "accent" : "neutral"}>{ident.role}</Badge>
            <Badge tone={console.tone}>{console.text}</Badge>
            <Badge>{ident.tools.length ? `${ident.tools.length} tools` : "no tool rights"}</Badge>
          </span>
        }
      />
      <CardBody className="space-y-2 text-sm">
        {rotated && <OneTimeSecret title={`New API token for ${ident.id}`} value={rotated} />}
        <Row label="Granted tools"><Pills values={ident.tools} tone="ok" /></Row>
        <Row label="Scopes"><Pills values={ident.scopes} tone="accent" /></Row>
        {ident.unknown_tools.length > 0 && (
          <Notice tone="bad">
            <strong>Rights on unknown tools.</strong> These IDs appear in no catalog:{" "}
            <Pills values={ident.unknown_tools} tone="deny" />
          </Notice>
        )}
        {canWrite && (
          <div className="flex flex-wrap items-start gap-1 pt-1">
            <Button size="sm" variant="outline" onClick={onEdit}>Edit</Button>
            <ConfirmButton
              label="Rotate token" question={`Issue a new token for ${ident.id}?`}
              busy={rotate.isPending} onConfirm={() => rotate.mutateAsync(undefined)}
            >
              <span className="text-xs text-muted-foreground">The current token stops working at once.</span>
            </ConfirmButton>
            <ConfirmButton
              label="Delete" question={`Delete ${ident.id}?`}
              busy={remove.isPending} onConfirm={() => remove.mutateAsync(undefined)}
            >
              <span className="text-xs text-muted-foreground">
                Its token stops working immediately; an agent still using it gets an authentication failure.
              </span>
            </ConfirmButton>
          </div>
        )}
        <WriteError error={rotate.error ?? remove.error} />
      </CardBody>
    </Card>
  );
}

function IdentityEditor({ current, onDone, onReload }: {
  current?: Identity;
  onDone: (token?: TokenIssued) => void;
  onReload: () => Promise<unknown>;
}) {
  const { session } = useAuth();
  const tools = useQuery({ queryKey: ["tools"], queryFn: () => apiGet("/tools") });
  const [id, setId] = useState(current?.id ?? "");
  const [role, setRole] = useState<string>(current?.role ?? "agent");
  const [granted, setGranted] = useState<Set<string>>(new Set(current?.tools ?? []));
  const [scopes, setScopes] = useState((current?.scopes ?? []).join("\n"));
  const [password, setPassword] = useState("");
  // The revision this form was opened on, not whatever the list was last
  // refetched at: a live update rereads the list while the form is open,
  // and saving the form's older view on top of it must answer 412.
  const [etag, setEtag] = useState(() => etagFor(LIST));
  const save = useWrite(
    () => {
      const body = {
        id: id.trim(), role, tools: [...granted].sort(),
        scopes: scopes.split("\n").map((s) => s.trim()).filter(Boolean), password,
      };
      return current
        ? apiSend("PUT", `${LIST}/${encodeURIComponent(current.id)}`, { body, ifMatch: etag }).then(() => undefined)
        : apiSend<TokenIssued>("POST", LIST, { body, ifMatch: etag });
    },
    // Editing yourself (a new password, say) may end your own session.
    current?.id === session?.identity ? [...INVALIDATES, ["session"]] : INVALIDATES,
    (token) => onDone(token ?? undefined),
  );
  const choices = tools.data ? tools.data.tools.map((t) => t.id).sort() : [];
  const consoleRole = role === "viewer" || role === "admin";
  return (
    <Card>
      <CardHeader title={current ? `Edit ${current.id}` : "New identity"} />
      <CardBody>
        <form
          className="space-y-3"
          onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}
        >
          <WriteError
            error={save.error}
            // Reload means "I have seen the change": the next save is
            // based on the reread list.
            onReload={() => void onReload().then(() => { setEtag(etagFor(LIST)); save.reset(); })}
          />
          <div className="grid gap-3 sm:grid-cols-2">
            <Label text="ID">
              <Input value={id} onChange={(e) => setId(e.target.value)} required maxLength={64} autoComplete="off" />
            </Label>
            <Label text="Role">
              <Select value={role} onChange={(e) => setRole(e.target.value)}>
                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </Select>
            </Label>
          </div>
          {consoleRole && (
            <Label text={current ? "New console password (leave empty to keep)" : "Console password"}>
              <Input
                type="password" autoComplete="new-password" value={password}
                onChange={(e) => setPassword(e.target.value)} required={!current}
              />
            </Label>
          )}
          <fieldset className="space-y-1">
            <legend className="text-xs font-medium text-muted-foreground">Granted tools</legend>
            {choices.length === 0 ? (
              <p className="text-xs text-muted-foreground">No tools in the catalog yet.</p>
            ) : (
              <div className="grid gap-1 sm:grid-cols-2">
                {choices.map((tid) => (
                  <label key={tid} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox" checked={granted.has(tid)}
                      onChange={(e) => {
                        const next = new Set(granted);
                        if (e.target.checked) next.add(tid); else next.delete(tid);
                        setGranted(next);
                      }}
                    />
                    <code className="text-xs">{tid}</code>
                  </label>
                ))}
              </div>
            )}
          </fieldset>
          <Label text="Scopes, one per line">
            <Textarea className="font-mono text-xs" spellCheck={false} value={scopes} onChange={(e) => setScopes(e.target.value)} />
          </Label>
          <div className="flex gap-2">
            <Button type="submit" disabled={save.isPending}>{current ? "Save" : "Create and issue token"}</Button>
            <Button type="button" variant="ghost" onClick={() => onDone()}>Cancel</Button>
          </div>
        </form>
      </CardBody>
    </Card>
  );
}

export function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[10rem_minmax(0,1fr)]">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="min-w-0">{children}</div>
    </div>
  );
}
