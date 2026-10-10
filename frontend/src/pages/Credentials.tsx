import { useState } from "react";
import { useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink, Plus } from "lucide-react";
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
      <OAuthResult />
      {writable && <OAuthConnect />}
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

/** The text for each result code the OAuth callback sends back. Only the
 * code travels in the URL, so nothing a provider sent is ever shown. */
const OAUTH_RESULT: Record<string, { tone: "good" | "bad"; text: string }> = {
  ok: { tone: "good", text: "Connected. The refresh token is stored in the credential; nothing else changed." },
  denied: { tone: "bad", text: "The provider did not grant access (cancelled, or the client may not ask for these scopes). Nothing was changed." },
  no_code: { tone: "bad", text: "The provider sent no authorization code back. Nothing was changed." },
  no_refresh_token: {
    tone: "bad",
    text: "The provider returned no refresh token. Remove gatekeeper's access in your account's app permissions and connect again. Nothing was changed.",
  },
  exchange_failed: { tone: "bad", text: "Exchanging the code for a token failed. Check the client ID, secret and redirect URI. Nothing was changed." },
  credential_unusable: { tone: "bad", text: "The credential does not hold a usable client_id/client_secret bundle. Nothing was changed." },
  role_required: { tone: "bad", text: "The account that started this sign-in can no longer write credentials. Nothing was changed." },
  read_only: { tone: "bad", text: "This console cannot write credentials. Nothing was changed." },
  write_refused: { tone: "bad", text: "The credential store refused the write. Nothing was changed." },
  state_mismatch: {
    tone: "bad",
    text: "This did not match a sign-in started from this console: it expired, was already used, or came from elsewhere. Start again here. Nothing was changed.",
  },
};

function OAuthResult() {
  const [params, setParams] = useSearchParams();
  const code = params.get("oauth");
  if (!code) return null;
  const result = OAUTH_RESULT[code] ?? { tone: "bad" as const, text: "The sign-in did not complete. Nothing was changed." };
  const credential = params.get("credential");
  const provider = params.get("provider");
  return (
    <Notice tone={result.tone}>
      <div className="flex items-start gap-2">
        <span className="flex-1">
          {provider && credential && <strong className="font-mono">{credential} ({provider}): </strong>}
          {result.text}
        </span>
        <Button size="sm" variant="ghost" onClick={() => setParams({}, { replace: true })}>Dismiss</Button>
      </div>
    </Notice>
  );
}

function OAuthConnect() {
  const providers = useQuery({ queryKey: ["oauth-providers"], queryFn: () => apiGet("/oauth/providers") });
  const [started, setStarted] = useState<Schemas["OAuthStart"] | null>(null);
  const start = useWrite(
    ({ provider, credential }: { provider: string; credential: string }) =>
      apiSend<Schemas["OAuthStart"]>("POST", `/oauth/${provider}/authorize`, { body: { credential } }),
    [],
    setStarted,
  );
  if (!providers.data?.length) return null;
  return (
    <Card>
      <CardHeader title="Sign in with a provider" />
      <CardBody className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Adds a refresh token to an oauth2 credential that already holds your OAuth client&apos;s
          client_id and client_secret.
        </p>
        <div className="flex flex-wrap gap-2">
          {providers.data.flatMap((p) => p.credentials.map((name) => (
            <Button
              key={`${p.key}/${name}`} size="sm" variant="outline" disabled={start.isPending}
              onClick={() => { setStarted(null); start.mutate({ provider: p.key, credential: name }); }}
            >
              Connect {p.label}: <span className="font-mono">{name}</span>
            </Button>
          )))}
        </div>
        <WriteError error={start.error} />
        {started && (
          <div className="space-y-2 rounded-md border border-border p-3">
            <Row label="Credential"><code>{started.credential}</code></Row>
            <Row label="Redirect URI">
              <code className="break-all">{started.callback_uri}</code>
              <p className="text-xs text-muted-foreground">
                Must be registered exactly like this in the {started.registration_console}, or {started.label} refuses
                with {started.mismatch_error}.
              </p>
            </Row>
            <Row label="Scopes"><Pills values={started.scopes} tone="accent" /></Row>
            <a
              href={started.consent_url}
              className="inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground"
            >
              Continue to {started.label} <ExternalLink className="size-3.5" aria-hidden />
            </a>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
