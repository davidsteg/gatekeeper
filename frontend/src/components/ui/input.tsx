import type { InputHTMLAttributes, SelectHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const field =
  "h-9 rounded-md border border-border bg-background px-3 text-sm placeholder:text-muted-foreground " +
  "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(field, className)} {...props} />;
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={cn(field, "pr-8", className)} {...props} />;
}

export function Label({ text, children }: { text: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-xs font-medium text-muted-foreground">
      {text}
      {children}
    </label>
  );
}
