import { NavLink, Outlet } from "react-router";
import {
  Activity, BarChart3, BookOpen, Boxes, FileText, Gauge, Inbox, KeyRound, Lock, LogOut, ScrollText, SlidersHorizontal, UserRound,
} from "lucide-react";
import { useAuth } from "@/auth";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useOpenRequestCount } from "@/pages/Requests";

const NAV = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/tools", label: "Tools", icon: SlidersHorizontal },
  { to: "/identities", label: "Identities", icon: KeyRound },
  { to: "/credentials", label: "Credentials", icon: Lock },
  { to: "/toolkits", label: "Toolkits", icon: Boxes },
  { to: "/requests", label: "Requests", icon: Inbox },
  { to: "/stats", label: "Stats", icon: BarChart3 },
  { to: "/audit", label: "Audit log", icon: Activity },
  { to: "/docs", label: "Docs", icon: FileText },
  { to: "/release-notes", label: "Release notes", icon: BookOpen },
  { to: "/account", label: "Account", icon: UserRound },
] as const;

export function Layout() {
  const { session, signOut } = useAuth();
  const open = useOpenRequestCount();
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="border-b border-border bg-card md:sticky md:top-0 md:h-screen md:w-56 md:border-r md:border-b-0">
        <div className="flex items-center gap-2 px-4 py-4">
          <ScrollText className="size-5 text-primary" aria-hidden />
          <span className="font-semibold">gatekeeper</span>
          <Badge className="ml-auto font-mono">{session?.version}</Badge>
        </div>
        <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col md:overflow-visible">
          {NAV.map(({ to, label, icon: Icon, ...rest }) => (
            <NavLink
              key={to}
              to={to}
              end={"end" in rest}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2 rounded-md px-3 py-2 text-sm whitespace-nowrap",
                  isActive ? "bg-primary/10 font-medium text-primary" : "hover:bg-muted",
                )
              }
            >
              <Icon className="size-4" aria-hidden />
              {label}
              {to === "/requests" && open > 0 && (
                <Badge tone="warn" className="ml-auto" aria-label={`${open} open`}>{open}</Badge>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="hidden border-t border-border px-4 py-3 text-xs md:block">
          <div className="font-mono">{session?.identity}</div>
          <div className="mt-1 flex items-center gap-1">
            <Badge tone={session?.role === "admin" ? "accent" : "neutral"}>{session?.role}</Badge>
            {session?.read_only && <Badge tone="warn">read-only</Badge>}
          </div>
          <button
            type="button"
            onClick={() => void signOut()}
            className="mt-3 inline-flex items-center gap-1 text-muted-foreground hover:text-foreground"
          >
            <LogOut className="size-3.5" aria-hidden /> Sign out
          </button>
        </div>
      </aside>
      <main className="mx-auto w-full max-w-6xl flex-1 space-y-4 p-4 md:p-6">
        <Outlet />
      </main>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-end gap-3">
      <div className="flex-1">
        <h1 className="text-xl font-semibold">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {actions}
    </header>
  );
}
