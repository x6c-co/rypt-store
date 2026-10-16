import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Link, Route, BrowserRouter, Routes } from "react-router";
import { ApiError } from "./api/errors";
import { handleGlobalError } from "./api/events";
import { AuthEvents, RequireAuth, SetupGate } from "./AppGate";
import { AppShell } from "./components/Layout";
import { ToastProvider } from "./components/Toast";
import { EmptyState } from "./components/ui";
import { AccountPage, TenantAuditPage } from "./pages/Account";
import { InstanceSettingsPage } from "./pages/InstanceSettings";
import { LoginPage, MfaChallengePage } from "./pages/Login";
import { MembersPage } from "./pages/Members";
import { ComparePage, EnvironmentPage, HomePage, ProjectLayout, TenantHomePage } from "./pages/Project";
import { ProjectSettingsPage } from "./pages/ProjectSettings";
import { DevicePage, InvitePage, MfaEnrollPage, ResetPasswordPage } from "./pages/Public";
import { SetupPage } from "./pages/Setup";

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    queryCache: new QueryCache({ onError: (err) => void handleGlobalError(err) }),
    mutationCache: new MutationCache({ onError: (err) => void handleGlobalError(err) }),
    defaultOptions: {
      queries: {
        // Client errors do not get better by retrying.
        retry: (count, err) => !(err instanceof ApiError && err.status < 500) && count < 2,
        refetchOnWindowFocus: true,
      },
    },
  });
}

function NotFound() {
  return (
    <EmptyState action={<Link to="/">Go to your projects</Link>}>
      There is nothing at this address.
    </EmptyState>
  );
}

/** Every route of the SPA. Server-generated links: /device, /invite/:token, /reset-password/:token. */
export function AppRoutes() {
  return (
    <SetupGate>
      <AuthEvents />
      <Routes>
        <Route path="/setup" element={<SetupPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/login/mfa" element={<MfaChallengePage />} />
        <Route path="/invite/:token" element={<InvitePage />} />
        <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
        <Route element={<RequireAuth enrollOnly />}>
          <Route path="/mfa/enroll" element={<MfaEnrollPage />} />
        </Route>
        <Route element={<RequireAuth />}>
          <Route path="/device" element={<DevicePage />} />
          <Route element={<AppShell />}>
            <Route index element={<HomePage />} />
            <Route path="/t/:tenant" element={<TenantHomePage />} />
            <Route path="/t/:tenant/p/:project" element={<ProjectLayout />}>
              <Route index element={<ComparePage />} />
              <Route path="e/:env" element={<EnvironmentPage />} />
              <Route path="settings" element={<ProjectSettingsPage />} />
            </Route>
            <Route path="/t/:tenant/members" element={<MembersPage />} />
            <Route path="/t/:tenant/audit" element={<TenantAuditPage />} />
            <Route path="/account" element={<AccountPage />} />
            <Route path="/settings" element={<InstanceSettingsPage />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Route>
      </Routes>
    </SetupGate>
  );
}

export function App({ client }: { client: QueryClient }) {
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </ToastProvider>
    </QueryClientProvider>
  );
}
