import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiGet, apiSend } from "@/api/client";
import { useWrite, WriteError } from "@/components/forms";
import { PageHeader } from "@/components/Layout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
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
        <>
          <Card>
            <CardBody className="space-y-2 text-sm">
              <Row label="Identity"><span className="font-mono">{query.data.identity}</span></Row>
              <Row label="Role"><Badge tone={query.data.role === "admin" ? "accent" : "neutral"}>{query.data.role}</Badge></Row>
            </CardBody>
          </Card>
          {query.data.can_change_password ? (
            <PasswordForm onReload={() => void query.refetch()} />
          ) : (
            <Notice>This deployment is read-only, so the password cannot be changed here.</Notice>
          )}
        </>
      )}
    </>
  );
}

function PasswordForm({ onReload }: { onReload: () => void }) {
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);
  const [mismatch, setMismatch] = useState(false);
  const save = useWrite(
    () => apiSend("PUT", "/account/password", { body: { current, password }, ifMatchOf: "/account" }),
    [["account"], ["identities"]],
    () => { setCurrent(""); setPassword(""); setConfirm(""); setDone(true); },
  );
  return (
    <Card>
      <CardHeader title="Change password" />
      <CardBody>
        <form
          className="max-w-md space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            setDone(false);
            setMismatch(password !== confirm);
            if (password === confirm) save.mutate(undefined);
          }}
        >
          {done && <Notice tone="good">Password changed. Every other session of this identity was signed out.</Notice>}
          {mismatch && <Notice tone="bad">The two new passwords do not match.</Notice>}
          <WriteError error={save.error} onReload={onReload} />
          <Label text="Current password">
            <Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          </Label>
          <Label text="New password">
            <Input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </Label>
          <Label text="New password, again">
            <Input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
          </Label>
          <Button type="submit" busy={save.isPending} busyLabel="Saving…">Change password</Button>
        </form>
      </CardBody>
    </Card>
  );
}
