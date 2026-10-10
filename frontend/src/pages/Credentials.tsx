import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Badge, Pills, type Tone } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { formatTime } from "@/lib/utils";
import { Row } from "./Identities";

const PROBE: Record<string, Tone> = {
  verified: "ok",
  auth_failed: "deny",
  unreachable: "warn",
  no_probe_url: "neutral",
};

export function Credentials() {
  const query = useQuery({ queryKey: ["credentials"], queryFn: () => apiGet("/credentials") });
  return (
    <>
      <PageHeader
        title="Credentials"
        subtitle="Named secrets a toolkit's credential: field refers to. Write-only: create, rotate, delete -- never read. This page shows metadata only."
      />
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
              </CardBody>
            </Card>
          ))}
        </>
      )}
    </>
  );
}
