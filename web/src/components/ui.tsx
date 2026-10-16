import { useId, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { errorMessage } from "../api/errors";
import { copyText } from "../lib/browser";
import { useToast } from "./Toast";

type Variant = "default" | "primary" | "danger" | "ghost" | "link";

export function Button({
  variant = "default",
  size,
  busy,
  children,
  className,
  type = "button",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: "sm"; busy?: boolean }) {
  const cls = ["btn", variant !== "default" && `btn-${variant}`, size === "sm" && "btn-sm", className].filter(Boolean).join(" ");
  return (
    <button type={type} className={cls} disabled={rest.disabled || busy} aria-busy={busy || undefined} {...rest}>
      {busy && <span className="spinner" aria-hidden="true" />}
      {children}
    </button>
  );
}

interface FieldProps {
  label: ReactNode;
  hint?: ReactNode;
  error?: string;
  children: (ids: { id: string; describedBy?: string; invalid: boolean }) => ReactNode;
}

/** A labelled form field that wires up hint and error descriptions. */
export function Field({ label, hint, error, children }: FieldProps) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errId = error ? `${id}-err` : undefined;
  const describedBy = [hintId, errId].filter(Boolean).join(" ") || undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children({ id, describedBy, invalid: !!error })}
      {hint && (
        <span className="hint" id={hintId}>
          {hint}
        </span>
      )}
      {error && (
        <span className="error" id={errId} role="alert">
          {error}
        </span>
      )}
    </div>
  );
}

export function TextField({
  label,
  hint,
  error,
  mono,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode; hint?: ReactNode; error?: string; mono?: boolean }) {
  return (
    <Field label={label} hint={hint} error={error}>
      {({ id, describedBy, invalid }) => (
        <input id={id} className={`input${mono ? " mono" : ""}`} aria-describedby={describedBy} aria-invalid={invalid || undefined} {...rest} />
      )}
    </Field>
  );
}

export function TextAreaField({
  label,
  hint,
  error,
  mono,
  ...rest
}: TextareaHTMLAttributes<HTMLTextAreaElement> & { label: ReactNode; hint?: ReactNode; error?: string; mono?: boolean }) {
  return (
    <Field label={label} hint={hint} error={error}>
      {({ id, describedBy, invalid }) => (
        <textarea id={id} className={`textarea${mono ? " mono" : ""}`} aria-describedby={describedBy} aria-invalid={invalid || undefined} {...rest} />
      )}
    </Field>
  );
}

export function SelectField({
  label,
  hint,
  error,
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement> & { label: ReactNode; hint?: ReactNode; error?: string }) {
  return (
    <Field label={label} hint={hint} error={error}>
      {({ id, describedBy, invalid }) => (
        <select id={id} className="select" aria-describedby={describedBy} aria-invalid={invalid || undefined} {...rest}>
          {children}
        </select>
      )}
    </Field>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function EmptyState({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <p>{children}</p>
      {action}
    </div>
  );
}

export function Notice({ tone = "info", children, title, role }: { tone?: "info" | "brass" | "crit" | "seal"; children: ReactNode; title?: string; role?: "alert" | "status" | "note" }) {
  return (
    <div className={`notice${tone !== "info" ? ` notice-${tone}` : ""}`} role={role}>
      {title && <strong>{title} </strong>}
      {children}
    </div>
  );
}

export function ErrorNotice({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <Notice tone="crit" role="alert">
      {errorMessage(error)}
    </Notice>
  );
}

export function Badge({ tone, children }: { tone?: "seal" | "crit" | "brass"; children: ReactNode }) {
  return <span className={`badge${tone ? ` badge-${tone}` : ""}`}>{children}</span>;
}

/** A read-only monospace value with a Copy button. */
export function CopyField({ value, label, copiedMessage }: { value: string; label: string; copiedMessage?: string }) {
  const toast = useToast();
  const id = useId();
  const [busy, setBusy] = useState(false);
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="copy-field">
        <input id={id} className="input mono" readOnly value={value} onFocus={(e) => e.currentTarget.select()} />
        <Button
          busy={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await copyText(value);
              toast.show(copiedMessage ?? "Copied.");
            } catch (err) {
              toast.error(errorMessage(err));
            } finally {
              setBusy(false);
            }
          }}
        >
          Copy
        </Button>
      </div>
    </div>
  );
}

export function KeyValue({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Progress({ done, total, label }: { done: number; total: number; label: string }) {
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  return (
    <div className="stack-sm">
      <div className="progress" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={total} aria-valuenow={done}>
        <span style={{ width: `${pct}%` }} />
      </div>
      <span className="small muted">
        {done} of {total} projects ({pct}%)
      </span>
    </div>
  );
}
