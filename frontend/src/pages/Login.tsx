import { useState, type FormEvent } from "react";
import { Navigate, useLocation, type Location } from "react-router";
import { useAuth } from "@/auth";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { Notice } from "@/components/ui/notice";

export function Login() {
  const { session, signIn } = useAuth();
  const [identity, setIdentity] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const from = (useLocation().state as { from?: Location } | null)?.from;

  // Router state is set only by this app (`RequireSession`), and a
  // `Location` is a path inside the router's basename: no way off /app.
  if (session) return <Navigate to={from ? `${from.pathname}${from.search}` : "/"} replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await signIn(identity.trim(), password);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sign-in failed.");
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardBody className="space-y-4">
          <div className="flex items-center gap-2">
            <Logo className="size-8" />
            <h1 className="text-lg font-semibold">gatekeeper console</h1>
          </div>
          <p className="text-sm text-muted-foreground">
            Sign in with your identity and console password. An API token does not work here.
          </p>
          {error && <Notice tone="bad">{error}</Notice>}
          <form className="space-y-3" onSubmit={(e) => void submit(e)}>
            <Label text="Identity">
              <Input
                name="identity" autoComplete="username" required value={identity}
                onChange={(e) => setIdentity(e.target.value)}
              />
            </Label>
            <Label text="Password">
              <Input
                name="password" type="password" autoComplete="current-password" required
                value={password} onChange={(e) => setPassword(e.target.value)}
              />
            </Label>
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardBody>
      </Card>
    </div>
  );
}
