// shadcn/ui-style primitives, copied in rather than depended on: the
// console carries no component library at runtime.
import type { ButtonHTMLAttributes } from "react";
import { Link, type LinkProps } from "react-router";
import { cn } from "@/lib/utils";

type Variant = "default" | "outline" | "ghost" | "destructive";
type Size = "sm" | "md";

const variants: Record<Variant, string> = {
  default: "bg-primary text-primary-foreground hover:bg-primary/90",
  outline: "border border-border bg-background hover:bg-muted",
  ghost: "hover:bg-muted",
  destructive: "bg-destructive text-white hover:bg-destructive/90",
};

export function buttonClass(variant: Variant = "default", size: Size = "md", className?: string): string {
  return cn(
    "inline-flex shrink-0 items-center justify-center gap-1.5 rounded-md font-medium whitespace-nowrap transition-colors",
    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
    "disabled:pointer-events-none disabled:opacity-50",
    // A little taller on a touch screen, where a 32px target is easy to miss.
    size === "sm" ? "h-9 px-3 text-xs sm:h-8 sm:px-2.5" : "h-10 px-3.5 text-sm sm:h-9",
    variants[variant],
    className,
  );
}

export function Button({
  className,
  variant = "default",
  size = "md",
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: Size }) {
  return <button type={type} className={buttonClass(variant, size, className)} {...props} />;
}

/** A link that looks like a button. Not a <button> inside an <a>: that is
 *  invalid HTML, and the pair takes two Tab stops for one action. */
export function LinkButton({
  className,
  variant = "default",
  size = "md",
  ...props
}: LinkProps & { variant?: Variant; size?: Size }) {
  return <Link className={buttonClass(variant, size, className)} {...props} />;
}
