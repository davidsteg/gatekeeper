import { useSyncExternalStore } from "react";
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** "2026-10-10T13:00:00+0200" -> local "13:00" / "Oct 10, 13:00". */
export function formatTime(ts: unknown, withDate = false): string {
  if (typeof ts !== "string") return "";
  const normalized = ts.replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return ts;
  return date.toLocaleString(undefined, withDate
    ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }
    : { hour: "2-digit", minute: "2-digit" });
}

/** True while the media query matches; false where matchMedia is missing
 *  (tests, very old browsers), which renders the desktop layout. */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      if (typeof window.matchMedia !== "function") return () => undefined;
      const list = window.matchMedia(query);
      list.addEventListener("change", onChange);
      return () => list.removeEventListener("change", onChange);
    },
    () => typeof window.matchMedia === "function" && window.matchMedia(query).matches,
    () => false,
  );
}

/** Below Tailwind's `md` breakpoint: a phone, or a narrow window. */
export function useIsNarrow(): boolean {
  return useMediaQuery("(max-width: 767.98px)");
}
