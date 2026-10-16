import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { api, call } from "../api/client";
import { ApiError } from "../api/errors";
import { qk, useMe } from "../api/queries";
import { PasskeyRegister, TotpEnroll } from "../components/MfaEnroll";
import { RecoveryCodes } from "../components/RecoveryCodes";
import { Button, ErrorNotice, KeyValue, Loading, Notice, TextField } from "../components/ui";
import { formatDateTime } from "../lib/format";
import { useAfterLogin } from "./Login";
import { passwordProblem } from "./Setup";

/** Forced MFA enrollment: the only flow a user without MFA can reach (core 7.2). */
export function MfaEnrollPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [codes, setCodes] = useState<string[] | null>(null);
  const [method, setMethod] = useState<"totp" | "webauthn">("totp");

  if (codes) {
    return (
      <div className="card-center" style={{ maxWidth: 560 }}>
        <div className="panel stack">
          <h1>Two-factor sign-in is on</h1>
          <RecoveryCodes codes={codes} />
          <div>
            <Button
              variant="primary"
              onClick={async () => {
                await qc.invalidateQueries({ queryKey: qk.me });
                navigate("/", { replace: true });
              }}
            >
              Continue
            </Button>
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className="card-center" style={{ maxWidth: 560 }}>
      <div className="panel stack">
        <h1>Set up two-factor sign-in</h1>
        <p className="muted">This server requires a second factor. Add an authenticator app or a passkey to continue.</p>
        <div className="row" role="group" aria-label="Method">
          <Button variant={method === "totp" ? "primary" : "default"} aria-pressed={method === "totp"} onClick={() => setMethod("totp")}>
            Authenticator app
          </Button>
          <Button variant={method === "webauthn" ? "primary" : "default"} aria-pressed={method === "webauthn"} onClick={() => setMethod("webauthn")}>
            Passkey
          </Button>
        </div>
        {method === "totp" ? <TotpEnroll onEnrolled={setCodes} /> : <PasskeyRegister onRegistered={setCodes} />}
        <Button
          variant="link"
          onClick={async () => {
            try {
              await call(api.POST("/api/v1/auth/logout"));
            } finally {
              qc.clear();
              navigate("/login", { replace: true });
            }
          }}
        >
          Sign out
        </Button>
      </div>
    </div>
  );
}

/** Browser approval for `rypt-store login` (core 7.4). */
export function DevicePage() {
  const [params, setParams] = useSearchParams();
  const code = (params.get("code") ?? "").trim().toUpperCase();
  const [typed, setTyped] = useState("");
  const [decided, setDecided] = useState<"approved" | "denied" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const req = useQuery({
    queryKey: ["device", code],
    queryFn: () => call(api.GET("/api/v1/auth/device/requests/{user_code}", { params: { path: { user_code: code } } })),
    enabled: !!code,
    retry: false,
  });

  const decide = async (approve: boolean) => {
    setBusy(true);
    setError(null);
    try {
      await call(api.POST("/api/v1/auth/device/approve", { body: { user_code: code, approve } }));
      setDecided(approve ? "approved" : "denied");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card-center">
      <div className="panel stack">
        <h1>Sign in the rypt-store CLI</h1>
        {!code ? (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              setParams({ code: typed.trim().toUpperCase() });
            }}
          >
            <TextField label="Code shown in your terminal" value={typed} onChange={(e) => setTyped(e.target.value)} mono required autoFocus autoComplete="off" />
            <div>
              <Button type="submit" variant="primary">
                Continue
              </Button>
            </div>
          </form>
        ) : decided ? (
          <Notice tone={decided === "approved" ? "seal" : "info"} role="status">
            {decided === "approved" ? "Approved. You can return to your terminal." : "Denied. The CLI will not be signed in."}
          </Notice>
        ) : req.isPending ? (
          <Loading />
        ) : req.isError ? (
          <>
            <ErrorNotice error={req.error instanceof ApiError && req.error.status === 404 ? new Error("That code is unknown or has expired. Run rypt-store login again.") : req.error} />
            <Link to="/device">Enter another code</Link>
          </>
        ) : req.data.state !== "pending" ? (
          <Notice>This request was already {req.data.state}.</Notice>
        ) : (
          <div className="stack">
            <p>Check that this code matches the one in your terminal before you approve.</p>
            <p className="mono" style={{ fontSize: "1.6rem", letterSpacing: "0.12em", margin: 0 }} data-testid="device-code">
              {req.data.user_code}
            </p>
            <KeyValue
              items={[
                ["Client", req.data.client_name || "rypt-store CLI"],
                ["Requested", formatDateTime(req.data.created_at)],
                ["Expires", formatDateTime(req.data.expires_at)],
              ]}
            />
            <ErrorNotice error={error} />
            <div className="row">
              <Button variant="primary" busy={busy} onClick={() => decide(true)}>
                Approve
              </Button>
              <Button busy={busy} onClick={() => decide(false)}>
                Deny
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export function InvitePage() {
  const { token = "" } = useParams();
  const after = useAfterLogin();
  const me = useMe();
  const inv = useQuery({
    queryKey: ["invitation", token],
    queryFn: () => call(api.GET("/api/v1/auth/invitations/{token}", { params: { path: { token } } })),
    retry: false,
  });
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  if (inv.isPending) return <Loading />;
  if (inv.isError) {
    return (
      <div className="card-center">
        <ErrorNotice error={inv.error instanceof ApiError && inv.error.status === 404 ? new Error("This invitation is unknown, used, or expired.") : inv.error} />
      </div>
    );
  }
  const i = inv.data;
  const signedInAs = me.data?.user?.email;
  const accept = async (body?: { display_name: string; password: string }) => {
    setBusy(true);
    setError(null);
    try {
      await after(await call(api.POST("/api/v1/auth/invitations/{token}/accept", { params: { path: { token } }, body })), "/");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card-center">
      <div className="panel stack">
        <h1>Join {i.tenant_name}</h1>
        <KeyValue
          items={[
            ["Email", i.email],
            ["Role", i.role],
            ["Expires", formatDateTime(i.expires_at)],
          ]}
        />
        {i.existing_user ? (
          signedInAs && signedInAs.toLowerCase() === i.email.toLowerCase() ? (
            <>
              <ErrorNotice error={error} />
              <div>
                <Button variant="primary" busy={busy} onClick={() => accept()}>
                  Accept invitation
                </Button>
              </div>
            </>
          ) : (
            <Notice>
              You already have an account. <Link to={`/login?next=${encodeURIComponent(`/invite/${token}`)}`}>Sign in as {i.email}</Link> to accept.
            </Notice>
          )
        ) : (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              setTouched(true);
              if (passwordProblem(password) || password !== confirm) return;
              void accept({ display_name: name.trim(), password });
            }}
          >
            <TextField label="Your name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} autoComplete="name" />
            <TextField
              label="Password"
              type="password"
              hint="At least 12 characters."
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="new-password"
              error={touched ? passwordProblem(password) : undefined}
            />
            <TextField
              label="Confirm password"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              autoComplete="new-password"
              error={touched && confirm !== password ? "The passwords do not match." : undefined}
            />
            <ErrorNotice error={error} />
            <div>
              <Button type="submit" variant="primary" busy={busy}>
                Accept invitation
              </Button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

export function ResetPasswordPage() {
  const { token = "" } = useParams();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [touched, setTouched] = useState(false);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  return (
    <div className="card-center">
      <div className="panel stack">
        <h1>Set a new password</h1>
        {done ? (
          <Notice tone="seal" role="status">
            Your password is changed and every session was signed out. <Link to="/login">Sign in</Link>.
          </Notice>
        ) : (
          <form
            className="stack"
            onSubmit={async (e) => {
              e.preventDefault();
              setTouched(true);
              if (passwordProblem(password) || password !== confirm) return;
              setBusy(true);
              setError(null);
              try {
                await call(api.POST("/api/v1/auth/password-reset", { body: { token, new_password: password } }));
                setDone(true);
              } catch (err) {
                setError(err);
              } finally {
                setBusy(false);
              }
            }}
          >
            <TextField
              label="New password"
              type="password"
              hint="At least 12 characters."
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="new-password"
              error={touched ? passwordProblem(password) : undefined}
            />
            <TextField
              label="Confirm password"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              autoComplete="new-password"
              error={touched && confirm !== password ? "The passwords do not match." : undefined}
            />
            <ErrorNotice error={error} />
            <div>
              <Button type="submit" variant="primary" busy={busy}>
                Set password
              </Button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
