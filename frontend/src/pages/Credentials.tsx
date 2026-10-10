import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { apiGet, apiSend, type Schemas } from "@/api/client";
import { useCanWrite } from "@/auth";
import { ConfirmButton, useWrite, WriteError } from "@/components/forms";
import { PageHeader } from "@/components/Layout";
import { Badge, Pills, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { formatTime } from "@/lib/utils";
import { Row } from "./Identities";

const PROBE: Record<string, Tone> = {
  verified: "ok",
  auth_failed: "deny",
  unreachable: "warn",
  no_probe_url: "neutral",
};

const LIST = "/credentials";
const INVALIDATES = [["credentials"], ["toolkits"]];

/** `credentials.KINDS`. Which ones need a header/parameter name. */
const KINDS = [
  "api_key_header", "basic", "bearer", "docker_tls", "oauth2", "ssh_password",
  "ssh_private_key", "url_path", "url_query", "ws_api_key",
] as const;
const NEEDS_HEADER = new Set(["api_key_header", "url_query"]);

export function Credentials() {
  const canWrite = useCanWrite();
  const [creating, setCreating] = useState(false);
  const query = useQuery({ queryKey: ["credentials"], queryFn: () => apiGet("/credentials") });
  const writable = canWrite && query.data?.configured === true;
  return (
    <>
      <PageHeader
        title="Credentials"
        subtitle="Named secrets a toolkit's credential: field refers to. Write-only: create, rotate, delete -- never read. This page shows metadata only."
        actions={writable && !creating && (
          <Button size="sm" onClick={() => setCreating(true)}><Plus className="size-3.5" /> New credential</Button>
        )}
      />
      {creating && (
        <CredentialForm
          dangling={query.data?.dangling ?? []}
          onDone={() => setCreating(false)} onReload={() => void query.refetch()}
        />
      )}
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        <>
          {!query.data.configured && (
            <Notice tone="bad">
              <strong>No credential store configured.</strong> Set GATEKEEPER_CREDENTIAL_KEY (or
              GATEKEEPER_CREDENTIAL_KEY_FILE) and restart to enable it.
            </Notice>
          )}
          {query.data.dangling.length > 0 && (
            <Notice tone="bad">
              <strong>Referenced but missing.</strong> Tier 1 names credentials the store does not hold:{" "}
              <Pills values={query.data.dangling} tone="deny" />
            </Notice>
          )}
          {query.data.configured && query.data.credentials.length === 0 && (
            <Notice>No credentials yet.</Notice>
          )}
          {query.data.credentials.map((c) => (
            <Card key={c.name}>
              <CardHeader
                title={<span className="font-mono">{c.name}</span>}
                actions={
                  <span className="flex gap-1">
                    <Badge tone="accent">{c.kind}</Badge>
                    <Badge tone={PROBE[c.probe_status] ?? "neutral"}>{c.probe_status.replace(/_/g, " ")}</Badge>
                    {c.in_overlap && <Badge tone="warn">rotation overlap</Badge>}
                    {c.suspect_status && <Badge tone="deny">suspect: {c.suspect_status}</Badge>}
                  </span>
                }
              />
              <CardBody className="space-y-2 text-sm">
                {c.header && <Row label="Header / parameter"><code>{c.header}</code></Row>}
                <Row label="Used by"><Pills values={c.used_by} empty="no toolkit" /></Row>
                <Row label="Created">{formatTime(c.created_at, true)}</Row>
                {c.rotated_at && <Row label="Rotated">{formatTime(c.rotated_at, true)}</Row>}
                {c.probe_url && <Row label="Probe URL"><code className="break-all">{c.probe_url}</code></Row>}
                {writable && <CredentialActions meta={c} onReload={() => void query.refetch()} />}
              </CardBody>
            </Card>
          ))}
        </>
      )}
    </>
  );
}

function CredentialForm({ dangling, onDone, onReload }: {
  dangling: string[];
  onDone: () => void;
  onReload: () => void;
}) {
  const [name, setName] = useState(dangling[0] ?? "");
  const [kind, setKind] = useState<string>("bearer");
  const [header, setHeader] = useState("");
  const [value, setValue] = useState("");
  const [probeUrl, setProbeUrl] = useState("");
  const save = useWrite(
    () => apiSend("POST", LIST, {
      body: {
        name: name.trim(), kind, value,
        header: header.trim() || null, probe_url: probeUrl.trim() || null,
      },
      ifMatchOf: LIST,
    }),
    INVALIDATES,
    () => { setValue(""); onDone(); },
  );
  return (
    <Card>
      <CardHeader title="New credential" />
      <CardBody>
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); save.mutate(undefined); }}>
          <WriteError error={save.error} onReload={onReload} />
          <div className="grid gap-3 sm:grid-cols-2">
            <Label text="Name">
              <Input value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} autoComplete="off" list="dangling-credentials" />
              <datalist id="dangling-credentials">{dangling.map((n) => <option key={n} value={n} />)}</datalist>
            </Label>
            <Label text="Kind">
              <Select value={kind} onChange={(e) => setKind(e.target.value)}>
                {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
              </Select>
            </Label>
          </div>
          {NEEDS_HEADER.has(kind) && (
            <Label text={kind === "url_query" ? "Query parameter name" : "Header name"}>
              <Input value={header} onChange={(e) => setHeader(e.target.value)} required autoComplete="off" />
            </Label>
          )}
          <Label text="Value (write-only: it is encrypted and never shown again)">
            <Input type="password" value={value} onChange={(e) => setValue(e.target.value)} required autoComplete="off" />
          </Label>
          <Label text="Probe URL (optional, checked in the background after saving)">
            <Input type="url" value={probeUrl} onChange={(e) => setProbeUrl(e.target.value)} autoComplete="off" />
          </Label>
          <div className="flex gap-2">
            <Button type="submit" disabled={save.isPending}>Create</Button>
            <Button type="button" variant="ghost" onClick={onDone}>Cancel</Button>
          </div>
        </form>
      </CardBody>
    </Card>
  );
}

function CredentialActions({ meta, onReload }: { meta: Schemas["CredentialMeta"]; onReload: () => void }) {
  const self = `${LIST}/${encodeURIComponent(meta.name)}`;
  const [rotating, setRotating] = useState(false);
  const [value, setValue] = useState("");
  const [overlap, setOverlap] = useState("0");
  const rotate = useWrite(
    () => apiSend("POST", `${self}/rotate`, {
      body: { value, overlap_seconds: Number(overlap) || 0 }, ifMatchOf: LIST,
    }),
    INVALIDATES,
    () => { setValue(""); setRotating(false); },
  );
  const remove = useWrite(() => apiSend("DELETE", self, { ifMatchOf: LIST }), INVALIDATES);
  return (
    <div className="space-y-2 pt-1">
      {rotating ? (
        <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); rotate.mutate(undefined); }}>
          <div className="grid gap-3 sm:grid-cols-[1fr_12rem]">
            <Label text="New value">
              <Input type="password" value={value} onChange={(e) => setValue(e.target.value)} required autoComplete="off" />
            </Label>
            <Label text="Old value keeps working (seconds)">
              <Input type="number" min={0} value={overlap} onChange={(e) => setOverlap(e.target.value)} />
            </Label>
          </div>
          <div className="flex gap-2">
            <Button size="sm" type="submit" disabled={rotate.isPending}>Rotate</Button>
            <Button size="sm" type="button" variant="ghost" onClick={() => setRotating(false)}>Cancel</Button>
          </div>
        </form>
      ) : (
        <div className="flex flex-wrap items-start gap-1">
          <Button size="sm" variant="outline" onClick={() => setRotating(true)}>Rotate</Button>
          <ConfirmButton
            label="Delete" question={`Delete ${meta.name}?`}
            busy={remove.isPending} onConfirm={() => remove.mutate(undefined)}
          >
            <span className="text-xs text-muted-foreground">
              A toolkit that references it can no longer authenticate; its tools fail at call time.
            </span>
          </ConfirmButton>
        </div>
      )}
      <WriteError error={rotate.error ?? remove.error} onReload={onReload} />
    </div>
  );
}
