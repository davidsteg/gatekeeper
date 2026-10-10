import { createContext, useContext, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, apiGet, apiSend, setCsrfToken, type Schemas } from "@/api/client";

export type SessionInfo = Schemas["SessionInfo"];

interface AuthState {
  session: SessionInfo | null;
  loading: boolean;
  signIn: (identity: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export const SESSION_KEY = ["session"] as const;

async function fetchSession(): Promise<SessionInfo | null> {
  try {
    const info = await apiGet("/session");
    setCsrfToken(info.csrf);
    return info;
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null;
    throw error;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const query = useQuery({ queryKey: SESSION_KEY, queryFn: fetchSession, staleTime: 60_000 });

  const value: AuthState = {
    session: query.data ?? null,
    loading: query.isPending,
    async signIn(identity, password) {
      const info = await apiSend<SessionInfo>("POST", "/session", { body: { identity, password } });
      setCsrfToken(info.csrf);
      client.setQueryData(SESSION_KEY, info);
    },
    async signOut() {
      try {
        await apiSend("DELETE", "/session");
      } finally {
        setCsrfToken("");
        // Not `client.clear()`: that would detach the mounted session
        // observer, and the page would never notice it was signed out.
        client.setQueryData(SESSION_KEY, null);
        client.removeQueries({ predicate: (q) => q.queryKey[0] !== SESSION_KEY[0] });
      }
    },
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth outside AuthProvider");
  return value;
}

/** True only for an admin on a writable deployment. Hides controls; the
 *  server enforces the same rule on every write. */
export function useCanWrite(): boolean {
  return useAuth().session?.can_write ?? false;
}
