import { cn } from "@/lib/utils";

/** The gatekeeper mark: the same file the browser uses as the favicon. */
export function Logo({ className }: { className?: string }) {
  return <img src="/app/favicon.svg" alt="" aria-hidden className={cn("size-6 shrink-0", className)} />;
}
