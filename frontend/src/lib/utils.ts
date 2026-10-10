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
