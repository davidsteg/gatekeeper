// Live updates: one EventSource on /api/v1/events per open console. The
// server sends only topic names ("requests", "audit", ...), never data;
// each topic invalidates the queries that show it, and React Query
// refetches the ones on screen through the normal typed reads.
//
// While the stream is up, pages stop their 15-second polling (a slow
// safety poll stays). While it is down, they poll as before, and a
// reconnect refetches everything, so nothing a dropped stream missed
// stays missing.
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { API_BASE } from "@/api/client";
import { SESSION_KEY } from "@/auth";

/** Poll interval while the stream is down, and the safety net while up. */
export const POLL_MS = 15_000;
export const SAFETY_POLL_MS = 120_000;

export type LiveState = "connecting" | "live" | "offline";

/** Query-key roots each server topic makes stale. */
const TOPIC_KEYS: Record<string, string[]> = {
  audit: ["audit"],
  overview: ["overview"],
  stats: ["stats"],
  requests: ["requests", "overview"],
  tools: ["tools", "tool", "overview"],
  identities: ["identities", "overview"],
  credentials: ["credentials", "oauth-providers"],
  toolkits: ["toolkits", "overview"],
};

export function invalidateTopics(client: QueryClient, topics: readonly string[]): void {
  const roots = new Set(topics.flatMap((t) => TOPIC_KEYS[t] ?? []));
  for (const root of roots) void client.invalidateQueries({ queryKey: [root] });
}

const LiveContext = createContext<LiveState>("offline");

/** After the browser gave up on the stream (an HTTP error rather than a
 *  dropped connection), try a fresh one this much later. */
const REOPEN_MS = 30_000;

export function LiveProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const supported = typeof EventSource !== "undefined";
  const [state, setState] = useState<LiveState>(supported ? "connecting" : "offline");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!supported) return;
    let wasLive = attempt > 0;
    let reopen: ReturnType<typeof setTimeout> | undefined;
    const source = new EventSource(`${API_BASE}/events`);
    source.addEventListener("ready", () => {
      // A reconnect: whatever happened while the stream was down is
      // fetched now rather than waited for.
      if (wasLive) void client.invalidateQueries({ predicate: (q) => q.queryKey[0] !== SESSION_KEY[0] });
      wasLive = true;
      setState("live");
    });
    source.addEventListener("change", (event) => {
      try {
        const { topics } = JSON.parse((event as MessageEvent<string>).data) as { topics: unknown };
        if (Array.isArray(topics)) invalidateTopics(client, topics.filter((t): t is string => typeof t === "string"));
      } catch {
        // A malformed event changes nothing; the safety poll still runs.
      }
    });
    source.onerror = () => {
      setState("offline");
      // EventSource retries a dropped connection by itself, but gives up
      // on an HTTP error: a 401 after the session ended, or a 503 when
      // too many streams are open. Re-checking the session sends a
      // signed-out console to the login page; otherwise try again later.
      if (source.readyState === EventSource.CLOSED) {
        void client.invalidateQueries({ queryKey: SESSION_KEY });
        reopen = setTimeout(() => setAttempt((n) => n + 1), REOPEN_MS);
      }
    };
    return () => {
      clearTimeout(reopen);
      source.close();
    };
  }, [client, supported, attempt]);

  return <LiveContext.Provider value={state}>{children}</LiveContext.Provider>;
}

export function useLiveState(): LiveState {
  return useContext(LiveContext);
}

/** `refetchInterval` for a page's queries: fast polling only while the
 *  stream is down. */
export function usePollInterval(): number {
  return useLiveState() === "live" ? SAFETY_POLL_MS : POLL_MS;
}
