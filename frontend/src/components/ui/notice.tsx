import type { ReactNode } from "react";
import { AlertTriangle, Info } from "lucide-react";
import { cn } from "@/lib/utils";

export function Notice({ tone = "info", children }: { tone?: "info" | "bad" | "good"; children: ReactNode }) {
  const Icon = tone === "bad" ? AlertTriangle : Info;
  return (
    <div
      role={tone === "bad" ? "alert" : "status"}
      className={cn(
        "flex gap-3 rounded-lg border p-3 text-sm",
        tone === "bad" && "border-deny/40 bg-deny/10",
        tone === "good" && "border-ok/40 bg-ok/10",
        tone === "info" && "border-border bg-muted/50",
      )}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="space-y-1">{children}</div>
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="space-y-3" aria-busy="true" aria-label={label}>
      <div className="h-24 animate-pulse rounded-lg bg-muted" />
      <div className="h-48 animate-pulse rounded-lg bg-muted" />
    </div>
  );
}

export function QueryError({ error }: { error: unknown }) {
  return (
    <Notice tone="bad">
      <strong>Could not load this page.</strong>
      <p>{error instanceof Error ? error.message : String(error)}</p>
    </Notice>
  );
}
