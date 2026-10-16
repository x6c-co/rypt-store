import { startRegistration } from "@simplewebauthn/browser";
import { useState } from "react";
import { api, call, type Schemas } from "../api/client";
import { errorMessage } from "../api/errors";
import { QRCode } from "./QRCode";
import { Button, ErrorNotice, TextField } from "./ui";

type JsonObject = Schemas["JsonObject"];

/** Enrolls a TOTP authenticator: QR code, then a code to confirm. */
export function TotpEnroll({ onEnrolled }: { onEnrolled(recoveryCodes: string[]): void }) {
  const [enrollment, setEnrollment] = useState<Schemas["TotpEnrollment"] | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const begin = async () => {
    setBusy(true);
    setError(null);
    try {
      setEnrollment(await call(api.POST("/api/v1/me/mfa/totp")));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await call(api.POST("/api/v1/me/mfa/totp/confirm", { body: { code: code.trim() } }));
      onEnrolled(res.recovery_codes);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  if (!enrollment) {
    return (
      <div className="stack-sm">
        <p className="muted">Use an authenticator app such as 1Password, Bitwarden, or Google Authenticator.</p>
        <div>
          <Button variant="primary" busy={busy} onClick={begin}>
            Set up authenticator app
          </Button>
        </div>
        <ErrorNotice error={error} />
      </div>
    );
  }
  return (
    <form
      className="stack-sm"
      onSubmit={(e) => {
        e.preventDefault();
        void confirm();
      }}
    >
      <TotpSecret enrollment={enrollment} />
      <TextField
        label="Code from the app"
        value={code}
        onChange={(e) => setCode(e.target.value)}
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9 ]*"
        required
        mono
      />
      <ErrorNotice error={error} />
      <div>
        <Button type="submit" variant="primary" busy={busy} disabled={code.trim().length < 6}>
          Confirm code
        </Button>
      </div>
    </form>
  );
}

/** The QR code and the secret in text, for manual entry. */
export function TotpSecret({ enrollment }: { enrollment: Schemas["TotpEnrollment"] }) {
  return (
    <div className="row" style={{ alignItems: "flex-start", gap: 20 }}>
      <QRCode value={enrollment.otpauth_url} label="QR code for your authenticator app" />
      <div className="stack-sm" style={{ minWidth: 0, flex: 1 }}>
        <span className="small muted">Scan the code, or enter this secret by hand:</span>
        <code className="mono" data-testid="totp-secret" style={{ overflowWrap: "anywhere" }}>
          {enrollment.secret}
        </code>
      </div>
    </div>
  );
}

/** Registers a passkey with WebAuthn. */
export function PasskeyRegister({ onRegistered }: { onRegistered(recoveryCodes: string[]): void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const register = async () => {
    setBusy(true);
    setError(null);
    try {
      const begin = await call(api.POST("/api/v1/me/mfa/webauthn/register/begin"));
      const opts = (begin.options as { publicKey?: JsonObject }).publicKey ?? begin.options;
      const credential = await startRegistration({ optionsJSON: opts as unknown as Parameters<typeof startRegistration>[0]["optionsJSON"] });
      const res = await call(
        api.POST("/api/v1/me/mfa/webauthn/register/finish", { body: { name: name.trim(), credential: credential as unknown as JsonObject } }),
      );
      setName("");
      onRegistered(res.recovery_codes);
    } catch (err) {
      setError(err instanceof Error && err.name === "NotAllowedError" ? "The passkey prompt was cancelled or timed out." : errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="stack-sm"
      onSubmit={(e) => {
        e.preventDefault();
        void register();
      }}
    >
      <TextField label="Passkey name" hint="For example, the device or security key it lives on." value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required />
      {error && (
        <div className="notice notice-crit" role="alert">
          {error}
        </div>
      )}
      <div>
        <Button type="submit" busy={busy} disabled={!name.trim()}>
          Add passkey
        </Button>
      </div>
    </form>
  );
}
