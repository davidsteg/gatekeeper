import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody } from "@/components/ui/card";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { Row } from "./Identities";

export function Account() {
  const query = useQuery({ queryKey: ["account"], queryFn: () => apiGet("/account") });
  return (
    <>
      <PageHeader
        title="Account"
        subtitle="Your console password. The API token of an identity is a separate credential."
      />
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        <Card>
          <CardBody className="space-y-2 text-sm">
            <Row label="Identity"><span className="font-mono">{query.data.identity}</span></Row>
            <Row label="Role"><Badge tone={query.data.role === "admin" ? "accent" : "neutral"}>{query.data.role}</Badge></Row>
            {query.data.can_change_password ? (
              <Notice>
                Changing the password moves here in a later release. Until then, use{" "}
                <a className="underline" href="/ui/account">the classic console</a>.
              </Notice>
            ) : (
              <Notice>This deployment is read-only, so the password cannot be changed here.</Notice>
            )}
          </CardBody>
        </Card>
      )}
    </>
  );
}
