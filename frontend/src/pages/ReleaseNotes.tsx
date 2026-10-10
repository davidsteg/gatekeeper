import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Loading, QueryError } from "@/components/ui/notice";
import { Markdown } from "./markdown";

export function ReleaseNotes() {
  const [search, setSearch] = useState("");
  const query = useQuery({
    queryKey: ["release-notes", search],
    queryFn: () => apiGet("/release-notes", { query: { search: search || undefined, limit: search ? 50 : 10 } }),
  });
  return (
    <>
      <PageHeader
        title="Release notes"
        subtitle="RELEASE.md as shipped in this image."
        actions={
          <Input
            aria-label="Search release notes" placeholder="Search…" value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        }
      />
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        <>
          <p className="text-xs text-muted-foreground">
            Showing {query.data.releases.length} of {query.data.total}.
          </p>
          {query.data.releases.map((r) => (
            <Card key={r.version}>
              <CardHeader
                title={<span className="font-mono">{r.version}</span>}
                actions={r.version === query.data.version ? <Badge tone="ok">running</Badge> : null}
              />
              <CardBody><Markdown text={r.notes} /></CardBody>
            </Card>
          ))}
        </>
      )}
    </>
  );
}
