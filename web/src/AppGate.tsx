import { useQueryClient } from "@tanstack/react-query";
import { useEffect, type ReactNode } from "react";
import { Navigate, Outlet, useLocation, useNavigate } from "react-router";
import { ApiError } from "./api/errors";
import { onAuthRedirect } from "./api/events";
import { qk, useMe, useSetupStatus } from "./api/queries";
import { ErrorNotice, Loading } from "./components/ui";
import { useSyncNotices } from "./session";

/** Paths reachable without a session. */
const PUBLIC = [/^\/login(\/|$)/, /^\/setup$/, /^\/invite\//, /^\/reset-password\//];

export function isPublicPath(path: string): boolean {
  return PUBLIC.some((re) => re.test(path));
}

function nextParam(loc: { pathname: string; search: string }): string {
  return encodeURIComponent(loc.pathname + loc.search);
}

/** Sends every route to the setup wizard until setup completes (core 10). */
export function SetupGate({ children }: { children: ReactNode }) {
  const status = useSetupStatus();
  const loc = useLocation();
  if (status.isPending) return <Loading />;
  if (status.isError) {
    return (
      <div className="card-center">
        <ErrorNotice error={status.error} />
      </div>
    );
  }
  if (status.data.setup_required && loc.pathname !== "/setup") return <Navigate to="/setup" replace />;
  if (!status.data.setup_required && loc.pathname === "/setup") return <Navigate to="/" replace />;
  return <>{children}</>;
}

/** Listens for auth errors from any request and redirects. */
export function AuthEvents() {
  const navigate = useNavigate();
  const loc = useLocation();
  const qc = useQueryClient();
  useEffect(
    () =>
      onAuthRedirect((to) => {
        const next = nextParam(loc);
        switch (to) {
          case "login":
            if (isPublicPath(loc.pathname)) return;
            qc.removeQueries({ queryKey: qk.me });
            navigate(`/login?next=${next}`, { replace: true });
            break;
          case "mfa":
            if (loc.pathname !== "/login/mfa") navigate(`/login/mfa?next=${next}`, { replace: true });
            break;
          case "enroll":
            if (loc.pathname !== "/mfa/enroll") navigate("/mfa/enroll", { replace: true });
            break;
          case "setup":
            void qc.invalidateQueries({ queryKey: qk.setup });
            navigate("/setup", { replace: true });
            break;
        }
      }),
    [navigate, loc, qc],
  );
  return null;
}

/**
 * Requires a signed-in user whose session has passed MFA. With enrollOnly,
 * the route is the forced MFA enrollment flow (core 7.2), reachable before
 * the second factor exists.
 */
export function RequireAuth({ enrollOnly = false }: { enrollOnly?: boolean }) {
  const me = useMe();
  const loc = useLocation();
  useSyncNotices(me.data);

  if (me.isPending) return <Loading />;
  if (me.isError) {
    const err = me.error;
    if (err instanceof ApiError) {
      if (err.code === "unauthorized") return <Navigate to={`/login?next=${nextParam(loc)}`} replace />;
      if (err.code === "mfa_required") return <Navigate to={`/login/mfa?next=${nextParam(loc)}`} replace />;
      if (err.code === "mfa_enrollment_required") return enrollOnly ? <Outlet /> : <Navigate to="/mfa/enroll" replace />;
    }
    return (
      <div className="card-center">
        <ErrorNotice error={err} />
      </div>
    );
  }
  const data = me.data;
  if (data.principal_kind !== "user") {
    return (
      <div className="card-center">
        <div className="notice notice-crit">This page needs a user sign-in, not a service token.</div>
      </div>
    );
  }
  const hasFactor = !!data.mfa && (data.mfa.totp || data.mfa.passkeys > 0);
  const needsEnroll = !!data.mfa?.required && !hasFactor;
  if (enrollOnly) {
    // Already enrolled users have nothing to do here.
    return needsEnroll ? <Outlet /> : <Navigate to="/" replace />;
  }
  if (data.session && !data.session.mfa_satisfied && hasFactor) {
    return <Navigate to={`/login/mfa?next=${nextParam(loc)}`} replace />;
  }
  if (needsEnroll) return <Navigate to="/mfa/enroll" replace />;
  return <Outlet />;
}
