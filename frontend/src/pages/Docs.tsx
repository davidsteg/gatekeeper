import { NavLink, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Card, CardBody } from "@/components/ui/card";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { cn } from "@/lib/utils";
import { Markdown } from "./markdown";

export function Docs() {
  const { slug = "readme" } = useParams();
  const index = useQuery({ queryKey: ["docs"], queryFn: () => apiGet("/documents"), staleTime: Infinity });
  const doc = useQuery({
    queryKey: ["docs", slug],
    queryFn: () => apiGet("/documents/{slug}", { path: { slug } }),
    staleTime: Infinity,
  });
  return (
    <>
      <PageHeader title="Docs" subtitle="The documentation shipped in this image." />
      {index.data && (
        <nav aria-label="Documents" className="flex flex-wrap gap-1">
          {index.data.map((d) => (
            <NavLink
              key={d.slug} to={`/docs/${d.slug}`}
              className={({ isActive }) => cn(
                "rounded-md px-3 py-1.5 text-sm",
                isActive || (d.slug === "readme" && slug === "readme") ? "bg-primary/10 font-medium text-primary" : "hover:bg-muted",
                !d.available && "text-muted-foreground",
              )}
            >
              {d.label}
            </NavLink>
          ))}
        </nav>
      )}
      {doc.isPending ? <Loading /> : doc.isError ? <QueryError error={doc.error} /> : (
        <Card>
          <CardBody>
            {doc.data.text
              ? <Markdown text={doc.data.text} />
              : <Notice>{doc.data.label} is not bundled with this installation.</Notice>}
          </CardBody>
        </Card>
      )}
    </>
  );
}
