import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export type Tone = "neutral" | "ok" | "warn" | "deny" | "accent";

const tones: Record<Tone, string> = {
  neutral: "bg-muted text-muted-foreground",
  ok: "bg-ok/15 text-ok",
  warn: "bg-warn/15 text-warn",
  deny: "bg-deny/15 text-deny",
  accent: "bg-primary/15 text-primary",
};

export function Badge({
  tone = "neutral",
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: Tone }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        tones[tone],
        className,
      )}
      {...props}
    />
  );
}

export function Pills({ values, tone = "neutral", empty = "none" }: {
  values: readonly string[];
  tone?: Tone;
  empty?: string;
}) {
  if (!values.length) return <span className="text-xs text-muted-foreground">{empty}</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {values.map((v) => (
        <Badge key={v} tone={tone} className="font-mono">{v}</Badge>
      ))}
    </span>
  );
}
