import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router";
import { api, call, type Schemas } from "../api/client";
import { ApiError } from "../api/errors";
import { qk, useSetupStatus } from "../api/queries";
import { TotpSecret } from "../components/MfaEnroll";
import { RecoveryCodes } from "../components/RecoveryCodes";
import { Button, ErrorNotice, KeyValue, Loading, TextField } from "../components/ui";

export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 1024;

export function passwordProblem(pw: string): string | undefined {
  if (pw.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters.`;
  if (pw.length > MAX_PASSWORD) return `Use at most ${MAX_PASSWORD} characters.`;
  return undefined;
}

type Step = "details" | "mfa" | "done";

/** The first-run setup wizard (core 10). */
export function SetupPage() {
  const status = useSetupStatus();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>("details");
  const [form, setForm] = useState({ setup_token: "", email: "", display_name: "", password: "", confirm: "", organization: "" });
  const [touched, setTouched] = useState(false);
  const [totp, setTotp] = useState<Schemas["TotpEnrollment"] | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [codes, setCodes] = useState<string[]>([]);

  if (status.isPending) return <Loading />;
  if (!status.data) return <ErrorNotice error={status.error} />;
  const s = status.data;

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const pwError = touched ? passwordProblem(form.password) : undefined;
  const confirmError = touched && form.confirm !== form.password ? "The passwords do not match." : undefined;
  const fieldError = (f: string) => (error instanceof ApiError ? error.fieldError(f) : undefined);

  const finish = async (totpSecret?: string, totpCode?: string) => {
    setBusy(true);
    setError(null);
    try {
      const res = await call(
        api.POST("/api/v1/setup", {
          body: {
            setup_token: form.setup_token.trim(),
            email: form.email.trim(),
            display_name: form.display_name.trim(),
            password: form.password,
            organization: form.organization.trim(),
            totp_secret: totpSecret,
            totp_code: totpCode,
          },
        }),
      );
      setCodes(res.recovery_codes);
      setStep("done");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const submitDetails = async () => {
    setTouched(true);
    if (passwordProblem(form.password) || form.confirm !== form.password) return;
    if (!s.require_mfa) {
      await finish();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setTotp(await call(api.POST("/api/v1/setup/totp", { body: { setup_token: form.setup_token.trim(), email: form.email.trim() } })));
      setStep("mfa");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const steps = s.require_mfa ? ["Administrator", "Two-factor sign-in", "Recovery codes"] : ["Administrator", "Recovery codes"];
  const current = step === "details" ? 0 : step === "mfa" ? 1 : steps.length - 1;

  return (
    <div className="card-center" style={{ maxWidth: 560 }}>
      <div className="panel stack">
        <div>
          <ol className="steps" aria-label="Setup steps" style={{ listStyle: "none", padding: 0, margin: "0 0 8px" }}>
            {steps.map((label, i) => (
              <li key={label} className={i === current ? "current" : undefined} aria-current={i === current ? "step" : undefined}>
                {i + 1}. {label}
              </li>
            ))}
          </ol>
          <h1>Set up rypt-store</h1>
        </div>

        {step === "details" && (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              void submitDetails();
            }}
          >
            <p className="muted">
              The setup token is printed once in the server log. With Docker Compose, run <code>docker compose logs rypt-store</code>.
            </p>
            <TextField label="Setup token" value={form.setup_token} onChange={set("setup_token")} required mono autoComplete="off" spellCheck={false} error={fieldError("setup_token")} />
            <TextField label="Organization" hint="The name of your first tenant." value={form.organization} onChange={set("organization")} required maxLength={128} error={fieldError("organization")} />
            <TextField label="Your name" value={form.display_name} onChange={set("display_name")} required maxLength={128} autoComplete="name" error={fieldError("display_name")} />
            <TextField label="Email" type="email" value={form.email} onChange={set("email")} required autoComplete="email" error={fieldError("email")} />
            <TextField
              label="Password"
              type="password"
              hint={`At least ${MIN_PASSWORD} characters.`}
              value={form.password}
              onChange={set("password")}
              required
              autoComplete="new-password"
              error={pwError ?? fieldError("password")}
            />
            <TextField label="Confirm password" type="password" value={form.confirm} onChange={set("confirm")} required autoComplete="new-password" error={confirmError} />
            <div className="panel" style={{ background: "var(--paper)" }}>
              <h2 className="small muted" style={{ marginBottom: 8 }}>
                Set in the config file
              </h2>
              <KeyValue
                items={[
                  ["Key provider", <span className="mono">{s.provider}</span>],
                  ["Default key mode", <span className="mono">{s.default_key_mode}</span>],
                  ["TLS", <span className="mono">{s.tls_mode}</span>],
                  ["Two-factor sign-in", s.require_mfa ? "Required" : "Optional"],
                ]}
              />
            </div>
            <ErrorNotice error={error} />
            <div>
              <Button type="submit" variant="primary" busy={busy}>
                Continue
              </Button>
            </div>
          </form>
        )}

        {step === "mfa" && totp && (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              void finish(totp.secret, code.trim());
            }}
          >
            <p className="muted">Two-factor sign-in is required. Add rypt-store to an authenticator app, then enter the code it shows.</p>
            <TotpSecret enrollment={totp} />
            <TextField label="Code from the app" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required mono error={fieldError("totp_code")} />
            <ErrorNotice error={error} />
            <div className="row">
              <Button onClick={() => setStep("details")}>Back</Button>
              <Button type="submit" variant="primary" busy={busy} disabled={code.trim().length < 6}>
                Finish setup
              </Button>
            </div>
          </form>
        )}

        {step === "done" && (
          <div className="stack">
            <p>Setup is complete. You are signed in as {form.email}.</p>
            <RecoveryCodes codes={codes} />
            <div>
              <Button
                variant="primary"
                onClick={async () => {
                  await qc.invalidateQueries({ queryKey: qk.setup });
                  await qc.invalidateQueries({ queryKey: qk.me });
                  navigate("/", { replace: true });
                }}
              >
                Continue to rypt-store
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
