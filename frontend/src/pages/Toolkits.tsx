import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/api/client";
import { PageHeader } from "@/components/Layout";
import { Badge, Pills } from "@/components/ui/badge";
import { LinkButton } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { CodeBlock, CopyButton } from "@/components/ui/copy";
import { Loading, Notice, QueryError } from "@/components/ui/notice";
import { Row } from "./Identities";

// Read-only on purpose (FR-4.11): a toolkit grants access to real binaries
// and hosts, so creating or changing one is a deploy-time decision. There is
// no write control on this page and no write route behind it.
export function Toolkits() {
  const query = useQuery({ queryKey: ["toolkits"], queryFn: () => apiGet("/toolkits") });
  return (
    <>
      <PageHeader
        title="Toolkits"
        subtitle="Tier 1 boundaries from toolkits.yaml. Read-only: change them by editing the file and redeploying."
        actions={<LinkButton to="/toolkits/reference" variant="outline" size="sm">Reference YAML</LinkButton>}
      />
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        query.data.toolkits.length === 0 ? (
          <Notice><strong>No toolkits configured.</strong> Edit toolkits.yaml and redeploy.</Notice>
        ) : query.data.toolkits.map((tk) => (
          <Card key={tk.name}>
            <CardHeader
              title={<span className="font-mono">{tk.name}</span>}
              actions={<Badge tone="accent">{tk.executor}</Badge>}
            />
            <CardBody className="space-y-2 text-sm">
              {tk.target && <Row label="Target"><code className="break-all">{tk.target}</code></Row>}
              {tk.binaries.length > 0 && <Row label="Binaries"><Pills values={tk.binaries} /></Row>}
              {tk.denied_args.length > 0 && <Row label="Denied arguments"><Pills values={tk.denied_args} tone="deny" /></Row>}
              {tk.path_roots.length > 0 && <Row label="Path roots"><Pills values={tk.path_roots} /></Row>}
              {tk.protected_resources.length > 0 && (
                <Row label="Protected"><Pills values={tk.protected_resources} tone="deny" /></Row>
              )}
              {tk.destinations.length > 0 && <Row label="Destinations"><Pills values={tk.destinations} /></Row>}
              {tk.credential && <Row label="Credential"><code>{tk.credential}</code></Row>}
              {tk.run_as && <Row label="Runs as"><Badge tone="deny">{tk.run_as}</Badge></Row>}
              <Row label="Ceilings">
                <Pills values={[`timeout ≤ ${tk.max_timeout_seconds}s`, `output ≤ ${tk.max_output_bytes} B`]} />
              </Row>
            </CardBody>
          </Card>
        ))
      )}
    </>
  );
}

export function ToolkitReference() {
  const query = useQuery({ queryKey: ["toolkit-reference"], queryFn: () => apiGet("/toolkits/reference") });
  return (
    <>
      <PageHeader
        title="Toolkit reference"
        subtitle="Paste a block under toolkits: in toolkits.yaml, fill in the CHANGEME placeholders, then redeploy. This page cannot write the file for you (FR-4.11)."
      />
      {query.isPending ? <Loading /> : query.isError ? <QueryError error={query.error} /> : (
        query.data.map((ref) => (
          <Card key={ref.key} id={ref.key}>
            <CardHeader title={ref.display_name} actions={<CopyButton text={ref.toolkit_yaml} label="Copy YAML" />} />
            <CardBody className="space-y-2">
              {ref.notes && <p className="text-sm text-muted-foreground">{ref.notes}</p>}
              <CodeBlock text={ref.toolkit_yaml} />
            </CardBody>
          </Card>
        ))
      )}
    </>
  );
}
