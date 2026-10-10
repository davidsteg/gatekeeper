import { Navigate, Outlet, Route, Routes } from "react-router";
import { useAuth } from "@/auth";
import { Layout } from "@/components/Layout";
import { Loading } from "@/components/ui/notice";
import { Account } from "@/pages/Account";
import { Audit } from "@/pages/Audit";
import { Credentials } from "@/pages/Credentials";
import { Identities } from "@/pages/Identities";
import { Login } from "@/pages/Login";
import { Overview } from "@/pages/Overview";
import { ReleaseNotes } from "@/pages/ReleaseNotes";
import { ToolkitReference, Toolkits } from "@/pages/Toolkits";
import { Integrations, ToolDetail, Tools } from "@/pages/Tools";

function RequireSession() {
  const { session, loading } = useAuth();
  if (loading) return <div className="p-6"><Loading label="Checking session" /></div>;
  if (!session) return <Navigate to="/login" replace />;
  return <Outlet />;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<RequireSession />}>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="tools" element={<Tools />} />
          <Route path="tools/integrations" element={<Integrations />} />
          <Route path="tools/:toolId" element={<ToolDetail />} />
          <Route path="identities" element={<Identities />} />
          <Route path="credentials" element={<Credentials />} />
          <Route path="toolkits" element={<Toolkits />} />
          <Route path="toolkits/reference" element={<ToolkitReference />} />
          <Route path="audit" element={<Audit />} />
          <Route path="release-notes" element={<ReleaseNotes />} />
          <Route path="account" element={<Account />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}
