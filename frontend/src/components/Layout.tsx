import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import {
  Activity, BarChart3, BookOpen, Boxes, FileText, Gauge, Inbox, KeyRound, Lock, LogOut, Menu, SlidersHorizontal, UserRound, X,
} from "lucide-react";
import { useAuth } from "@/auth";
import { Logo } from "@/components/Logo";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { LiveProvider, useLiveState } from "@/live";
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
  return (
    <LiveProvider>
      <Shell />
    </LiveProvider>
  );
}

/** Whether new requests and calls arrive by themselves right now. */
function LiveIndicator() {
  const state = useLiveState();
  const label = state === "live" ? "Live" : state === "connecting" ? "Connecting" : "Polling";
  const title = state === "live"
    ? "Changes appear as they happen."
    : "No live connection: pages refresh every 15 seconds.";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground" title={title} role="status">
      <span
        aria-hidden
        className={cn("size-2 rounded-full", state === "live" ? "bg-ok" : state === "connecting" ? "bg-warn" : "bg-muted-foreground")}
      />
      {label}
    </span>
  );
}

/** The five a phone needs within thumb reach; the rest sit under More. */
const TABS = ["/", "/requests", "/tools", "/audit"] as const;

function NavItems({ open, onPick, className }: { open: number; onPick?: () => void; className?: string }) {
  return NAV.map(({ to, label, icon: Icon, ...rest }) => (
    <NavLink
      key={to}
      to={to}
      end={"end" in rest}
      onClick={onPick}
      className={({ isActive }) =>
        cn(
          "flex items-center gap-2 rounded-md px-3 py-2 text-sm whitespace-nowrap",
          isActive ? "bg-primary/10 font-medium text-primary" : "hover:bg-muted",
          className,
        )
      }
    >
      <Icon className="size-4" aria-hidden />
      {label}
      {to === "/requests" && open > 0 && (
        <Badge tone="warn" className="ml-auto" aria-label={`${open} open`}>{open}</Badge>
      )}
    </NavLink>
  ));
}

function WhoAmI() {
  const { session, signOut } = useAuth();
  return (
    <div className="text-xs">
      <div className="font-mono break-all">{session?.identity}</div>
      <div className="mt-1 flex items-center gap-1">
        <Badge tone={session?.role === "admin" ? "accent" : "neutral"}>{session?.role}</Badge>
        {session?.read_only && <Badge tone="warn">read-only</Badge>}
      </div>
      <button
        type="button"
        onClick={() => void signOut()}
        className="mt-3 inline-flex min-h-9 items-center gap-1 text-muted-foreground hover:text-foreground"
      >
        <LogOut className="size-3.5" aria-hidden /> Sign out
      </button>
    </div>
  );
}

function Shell() {
  const { session } = useAuth();
  const open = useOpenRequestCount();
  const [menu, setMenu] = useState(false);
  const { pathname } = useLocation();
  // Under "More" is any page that is not one of the tabs.
  const inMore = !TABS.some((t) => (t === "/" ? pathname === "/" : pathname.startsWith(t)));
  return (
    <div className="flex min-h-dvh flex-col md:flex-row">
      {/* Desktop: the sidebar. */}
      <aside className="hidden border-r border-border bg-card md:sticky md:top-0 md:flex md:h-screen md:w-56 md:shrink-0 md:flex-col">
        <div className="flex items-center gap-2 px-4 py-4">
          <Logo />
          <span className="font-semibold">gatekeeper</span>
          <span className="ml-auto"><LiveIndicator /></span>
        </div>
        <nav aria-label="Main" className="flex min-h-0 flex-1 flex-col gap-1 overflow-y-auto px-2 pb-2">
          <NavItems open={open} />
        </nav>
        <div className="border-t border-border px-4 py-3">
          <WhoAmI />
          {/* Down here, not next to the name: the header has no room for it
              beside the live indicator in a 14rem sidebar. */}
          <div className="mt-2 text-xs text-muted-foreground">
            Version <span className="font-mono">{session?.version}</span>
          </div>
        </div>
      </aside>

      {/* Phone: a slim top bar, tabs at the bottom, everything else under More. */}
      <header className="sticky top-0 z-20 flex items-center gap-2 border-b border-border bg-card/95 px-4 pt-[env(safe-area-inset-top)] backdrop-blur md:hidden">
        <span className="flex h-12 items-center gap-2">
          <Logo />
          <span className="font-semibold">gatekeeper</span>
        </span>
        <span className="ml-auto"><LiveIndicator /></span>
      </header>
      <nav
        aria-label="Tabs"
        className="fixed inset-x-0 bottom-0 z-30 grid grid-cols-5 border-t border-border bg-card/95 pb-[env(safe-area-inset-bottom)] backdrop-blur md:hidden"
      >
        {TABS.map((to) => {
          const item = NAV.find((n) => n.to === to);
          if (!item) return null;
          const Icon = item.icon;
          return (
            <NavLink
              key={to} to={to} end={to === "/"}
              className={({ isActive }) => cn(
                "relative flex h-14 flex-col items-center justify-center gap-0.5 text-[11px]",
                isActive ? "font-medium text-primary" : "text-muted-foreground",
              )}
            >
              <Icon className="size-5" aria-hidden />
              {to === "/audit" ? "Audit" : item.label}
              {to === "/requests" && open > 0 && (
                <span
                  aria-label={`${open} open`}
                  className="absolute top-1.5 left-1/2 ml-2 min-w-4 rounded-full bg-warn px-1 text-center text-[10px] leading-4 font-semibold text-background"
                >
                  {open}
                </span>
              )}
            </NavLink>
          );
        })}
        <button
          type="button" aria-expanded={menu} aria-controls="more-menu"
          onClick={() => setMenu(true)}
          className={cn(
            "flex h-14 flex-col items-center justify-center gap-0.5 text-[11px]",
            inMore ? "font-medium text-primary" : "text-muted-foreground",
          )}
        >
          <Menu className="size-5" aria-hidden />
          More
        </button>
      </nav>
      {menu && <MoreSheet open={open} onClose={() => setMenu(false)} />}

      <main className="mx-auto w-full min-w-0 max-w-6xl flex-1 space-y-4 p-4 pb-[calc(5rem+env(safe-area-inset-bottom))] md:p-6">
        <Outlet />
      </main>
    </div>
  );
}

/** Every page, the version, and who is signed in -- the phone's sidebar. */
function MoreSheet({ open, onClose }: { open: number; onClose: () => void }) {
  const { session } = useAuth();
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    panel.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    // The page behind must not scroll under the sheet.
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
    };
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-40 md:hidden">
      <button type="button" aria-label="Close menu" className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div
        id="more-menu" ref={panel} role="dialog" aria-modal="true" aria-label="All pages" tabIndex={-1}
        className="absolute inset-x-0 bottom-0 max-h-[85dvh] overflow-y-auto rounded-t-xl border-t border-border bg-card p-3 pb-[calc(1rem+env(safe-area-inset-bottom))] shadow-lg outline-none"
      >
        <div className="flex items-center gap-2 px-1 pb-2">
          <span className="text-sm font-semibold">All pages</span>
          <Badge className="font-mono">{session?.version}</Badge>
          <button type="button" onClick={onClose} aria-label="Close" className="ml-auto rounded-md p-2 hover:bg-muted">
            <X className="size-5" aria-hidden />
          </button>
        </div>
        <nav aria-label="All pages" className="grid grid-cols-2 gap-1">
          <NavItems open={open} onPick={onClose} className="min-h-11" />
        </nav>
        <div className="mt-3 border-t border-border px-2 pt-3"><WhoAmI /></div>
      </div>
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
      <div className="min-w-[min(100%,16rem)] flex-1">
        <h1 className="text-xl font-semibold">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {actions}
    </header>
  );
}
