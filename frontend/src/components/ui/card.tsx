import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("rounded-lg border border-border bg-card text-card-foreground shadow-xs", className)}
      {...props}
    />
  );
}

export function CardHeader({
  title,
  icon,
  actions,
  className,
}: {
  title: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    // Wraps rather than overflows: a long ID plus three badges does not fit
    // a phone's width, and the badges went off the card's edge.
    <div className={cn("flex flex-wrap items-center gap-x-2 gap-y-1.5 border-b border-border px-4 py-3", className)}>
      {icon}
      <h3 className="min-w-0 text-sm font-semibold wrap-break-word">{title}</h3>
      <span className="flex-1" />
      {actions}
    </div>
  );
}

export function CardBody({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-4", className)} {...props} />;
}
