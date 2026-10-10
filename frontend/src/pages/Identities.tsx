import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Badge, Pills } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Loading, Notice, QueryError } from "@/components/ui/notice";

const CONSOLE = {
  access: { tone: "ok", text: "console access" },
  no_password: { tone: "deny", text: "no console password" },
  api_only: { tone: "neutral", text: "api only" },
} as const;

export function Identities() {
  const query = useQuery({ queryKey: ["identities"], queryFn: () => apiGet("/identities") });
  return (
    <>
      <PageHeader
        title="Identities"
        subtitle="Rights attach to individual tool IDs, never to a whole toolkit. API tokens and console passwords are stored as scrypt hashes and are never shown."
      />
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        query.data.map((ident) => {
          const console = CONSOLE[ident.console];
          return (
            <Card key={ident.id}>
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
                <Row label="Granted tools"><Pills values={ident.tools} tone="ok" /></Row>
                <Row label="Scopes"><Pills values={ident.scopes} tone="accent" /></Row>
                {ident.unknown_tools.length > 0 && (
                  <Notice tone="bad">
                    <strong>Rights on unknown tools.</strong> These IDs appear in no catalog:{" "}
                    <Pills values={ident.unknown_tools} tone="deny" />
                  </Notice>
                )}
              </CardBody>
            </Card>
          );
        })
      )}
    </>
  );
}

export function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[10rem_1fr]">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div>{children}</div>
    </div>
  );
}
