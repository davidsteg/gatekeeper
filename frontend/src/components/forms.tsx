// Shared pieces of every write flow: a mutation hook that refreshes what
// it changed, an error notice that turns a 412 into "reload and retry",
// and a two-step confirm for anything destructive.
import { useEffect, useRef, useState, type ReactNode, type TextareaHTMLAttributes } from "react";
import { useMutation, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { ConflictError } from "@/api/client";
import { cn } from "@/lib/utils";
import { Button } from "./ui/button";
import { Notice } from "./ui/notice";

/** A write that, on success, refetches every query under `invalidates`. */
export function useWrite<TArgs, TResult>(
  fn: (args: TArgs) => Promise<TResult>,
  invalidates: QueryKey[],
  onSuccess?: (result: TResult) => void,
) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: async (result) => {
      await Promise.all(invalidates.map((key) => client.invalidateQueries({ queryKey: key })));
      onSuccess?.(result);
    },
  });
}

/** The server's sentence, as the form showed it. A 412 offers a reload:
 *  someone else changed the file, and blindly retrying would overwrite. */
export function WriteError({ error, onReload }: { error: unknown; onReload?: () => void }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : String(error);
  if (error instanceof ConflictError) {
    return (
      <Notice tone="bad">
        <strong>Changed elsewhere.</strong>
        <p>{message}</p>
        {onReload && <Button size="sm" variant="outline" onClick={onReload}>Reload</Button>}
      </Notice>
    );
  }
  return (
    <Notice tone="bad">
      <strong>Rejected.</strong>
      <p className="whitespace-pre-wrap">{message}</p>
    </Notice>
  );
}

export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        "min-h-24 rounded-md border border-border bg-background p-3 text-base sm:text-sm",
        "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring",
        className,
      )}
      {...props}
    />
  );
}

/** A destructive button that asks once, inline, before it acts. */
export function ConfirmButton({ label, question, onConfirm, busy, children }: {
  label: string;
  question: string;
  /** Return the write's promise: the question closes once it succeeds, so
   *  a second click cannot repeat a write nobody asked for twice. A
   *  failure leaves it open, with the error shown by the caller. */
  onConfirm: () => Promise<unknown>;
  busy?: boolean;
  children?: ReactNode;
}) {
  const [asking, setAsking] = useState(false);
  if (!asking) {
    return <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{label}</Button>;
  }
  return (
    <div role="group" aria-label={question} className="flex flex-wrap items-center gap-2 rounded-md border border-deny/40 bg-deny/10 p-2 text-sm">
      <span className="font-medium">{question}</span>
      {children}
      <Button size="sm" variant="destructive" disabled={busy}
        onClick={() => { onConfirm().then(() => setAsking(false), () => undefined); }}
      >Yes, {label.toLowerCase()}</Button>
      <Button size="sm" variant="ghost" onClick={() => setAsking(false)}>Cancel</Button>
    </div>
  );
}

/** A secret shown exactly once, with the reason it will not come back.
 *  It scrolls itself into view and takes the focus, so it is seen where it
 *  appears, and offers a copy button. `navigator.clipboard` only exists on
 *  HTTPS or localhost; on a plain-HTTP LAN deployment the button selects
 *  the text and falls back to the browser's copy command. */
export function OneTimeSecret({ title, value }: { title: string; value: string }) {
  // Which value was copied, so a new secret starts out uncopied.
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const copied = copiedValue === value;
  const box = useRef<HTMLDivElement>(null);
  const code = useRef<HTMLElement>(null);
  useEffect(() => {
    box.current?.scrollIntoView?.({ block: "nearest", behavior: "smooth" });
    box.current?.focus({ preventScroll: true });
  }, [value]);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedValue(value);
      return;
    } catch {
      // No clipboard API here (plain HTTP): select it and use the old command.
    }
    const selection = window.getSelection();
    if (code.current && selection) {
      const range = document.createRange();
      range.selectNodeContents(code.current);
      selection.removeAllRanges();
      selection.addRange(range);
      if (document.execCommand("copy")) setCopiedValue(value);
    }
  };
  return (
    <div ref={box} tabIndex={-1} className="outline-none">
      <Notice tone="good">
        <strong>{title}</strong>
        <p>Copy it now. It is stored only as a hash and cannot be shown again.</p>
        <div className="flex items-start gap-2">
          <code ref={code} data-testid="one-time-secret" className="block flex-1 break-all rounded bg-background p-2 font-mono text-xs">{value}</code>
          <Button size="sm" variant="outline" onClick={() => void copy()}>{copied ? "Copied" : "Copy"}</Button>
        </div>
      </Notice>
    </div>
  );
}
