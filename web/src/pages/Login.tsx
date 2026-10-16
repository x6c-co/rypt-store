import { startAuthentication } from "@simplewebauthn/browser";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { api, call, type Schemas } from "../api/client";
import { errorMessage } from "../api/errors";
import { qk } from "../api/queries";
import { Button, ErrorNotice, TextField } from "../components/ui";

const METHODS_KEY = "rypt-store:mfa-methods";
type Method = "totp" | "webauthn" | "recovery_code";

function saveMethods(m: Method[] | undefined) {
  try {
    if (m) sessionStorage.setItem(METHODS_KEY, JSON.stringify(m));
  } catch {
    // Not essential.
  }
}

function loadMethods(): Method[] {
  try {
    const v = JSON.parse(sessionStorage.getItem(METHODS_KEY) ?? "null") as unknown;
    if (Array.isArray(v) && v.length > 0) return v as Method[];
  } catch {
    // Fall through to every method.
  }
  return ["totp", "webauthn", "recovery_code"];
}

/** A safe in-app return path from ?next=. */
export function safeNext(next: string | null): string {
  if (!next) return "/";
  try {
    const decoded = decodeURIComponent(next);
    return decoded.startsWith("/") && !decoded.startsWith("//") && !decoded.startsWith("/login") ? decoded : "/";
  } catch {
    return "/";
  }
}

/** Follows a LoginResult to the next screen. */
export function useAfterLogin() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  return async (res: Schemas["LoginResult"], next: string) => {
    if (res.status === "mfa_required") {
      saveMethods(res.mfa_methods);
      navigate(`/login/mfa?next=${encodeURIComponent(next)}`, { replace: true });
      return;
    }
    await qc.invalidateQueries({ queryKey: qk.me });
    navigate(res.status === "mfa_enrollment_required" ? "/mfa/enroll" : next, { replace: true });
  };
}

export function LoginPage() {
  const [params] = useSearchParams();
  const next = safeNext(params.get("next"));
  const after = useAfterLogin();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  return (
    <div className="card-center">
      <form
        className="panel stack"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await after(await call(api.POST("/api/v1/auth/login", { body: { email: email.trim(), password } })), next);
          } catch (err) {
            setError(err);
          } finally {
            setBusy(false);
          }
        }}
      >
        <h1>Sign in to rypt-store</h1>
        <TextField label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="username" autoFocus />
        <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
        <ErrorNotice error={error} />
        <div className="row-between">
          <Button type="submit" variant="primary" busy={busy}>
            Sign in
          </Button>
          <span className="small muted">Forgot your password? Ask an owner of your tenant for a reset link.</span>
        </div>
      </form>
    </div>
  );
}

/** The second-factor step after the password (core 7.2). */
export function MfaChallengePage() {
  const [params] = useSearchParams();
  const next = safeNext(params.get("next"));
  const after = useAfterLogin();
  const methods = loadMethods();
  const [method, setMethod] = useState<Method>(methods.includes("totp") ? "totp" : (methods[0] ?? "totp"));
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const run = async (fn: () => Promise<Schemas["LoginResult"]>) => {
    setBusy(true);
    setError(null);
    try {
      await after(await fn(), next);
    } catch (err) {
      setError(err instanceof Error && err.name === "NotAllowedError" ? new Error("The passkey prompt was cancelled or timed out.") : err);
    } finally {
      setBusy(false);
    }
  };

  const passkey = () =>
    run(async () => {
      const begin = await call(api.POST("/api/v1/auth/mfa/webauthn/begin"));
      const opts = (begin.options as { publicKey?: unknown }).publicKey ?? begin.options;
      const credential = await startAuthentication({ optionsJSON: opts as Parameters<typeof startAuthentication>[0]["optionsJSON"] });
      return call(api.POST("/api/v1/auth/mfa/webauthn/finish", { body: { credential: credential as unknown as Schemas["JsonObject"] } }));
    });

  return (
    <div className="card-center">
      <div className="panel stack">
        <h1>Confirm it's you</h1>
        {method === "webauthn" ? (
          <div className="stack-sm">
            <p className="muted">Use a passkey registered to your account.</p>
            <div>
              <Button variant="primary" busy={busy} onClick={passkey}>
                Use a passkey
              </Button>
            </div>
          </div>
        ) : (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              void run(() =>
                method === "totp"
                  ? call(api.POST("/api/v1/auth/mfa/totp", { body: { code: code.trim() } }))
                  : call(api.POST("/api/v1/auth/mfa/recovery", { body: { code: code.trim() } })),
              );
            }}
          >
            <TextField
              key={method}
              label={method === "totp" ? "Code from your authenticator app" : "Recovery code"}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode={method === "totp" ? "numeric" : "text"}
              autoComplete="one-time-code"
              required
              mono
              autoFocus
            />
            <div>
              <Button type="submit" variant="primary" busy={busy}>
                Verify
              </Button>
            </div>
          </form>
        )}
        {error ? <div className="notice notice-crit" role="alert">{errorMessage(error)}</div> : null}
        <div className="stack-sm small">
          {methods.includes("totp") && method !== "totp" && (
            <Button variant="link" onClick={() => setMethod("totp")}>
              Use your authenticator app instead
            </Button>
          )}
          {methods.includes("webauthn") && method !== "webauthn" && (
            <Button variant="link" onClick={() => setMethod("webauthn")}>
              Use a passkey instead
            </Button>
          )}
          {methods.includes("recovery_code") && method !== "recovery_code" && (
            <Button variant="link" onClick={() => setMethod("recovery_code")}>
              Use a recovery code instead
            </Button>
          )}
          <Link to="/login">Sign in as someone else</Link>
        </div>
      </div>
    </div>
  );
}

