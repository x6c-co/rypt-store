import * as RDialog from "@radix-ui/react-dialog";
import { useState, type ReactNode } from "react";
import { errorMessage } from "../api/errors";
import { Button, ErrorNotice, TextField } from "./ui";

interface ModalProps {
  open: boolean;
  onOpenChange(open: boolean): void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  /** Renders as a side drawer instead of a centred dialog. */
  drawer?: boolean;
}

export function Modal({ open, onOpenChange, title, description, children, footer, wide, drawer }: ModalProps) {
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="dialog-overlay" />
        <RDialog.Content className={drawer ? "drawer" : `dialog${wide ? " wide" : ""}`}>
          <div className="row-between">
            <RDialog.Title className="dialog-title">{title}</RDialog.Title>
            <RDialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close">
                Close
              </Button>
            </RDialog.Close>
          </div>
          {description ? (
            <RDialog.Description className="dialog-description">{description}</RDialog.Description>
          ) : (
            <RDialog.Description className="visually-hidden">{typeof title === "string" ? title : "Dialog"}</RDialog.Description>
          )}
          {children}
          {footer && <div className="dialog-footer">{footer}</div>}
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}

interface ConfirmByNameProps {
  open: boolean;
  onOpenChange(open: boolean): void;
  title: string;
  description: ReactNode;
  /** The object's name, which the user must type (core 14.4). */
  name: string;
  /** Button label, e.g. "Delete secret". */
  action: string;
  onConfirm(): Promise<void> | void;
  danger?: boolean;
}

/** A destructive action that requires typing the object's name. */
export function ConfirmByName({ open, onOpenChange, title, description, name, action, onConfirm, danger = true }: ConfirmByNameProps) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const close = (o: boolean) => {
    if (!o) {
      setTyped("");
      setError(null);
    }
    onOpenChange(o);
  };
  return (
    <Modal
      open={open}
      onOpenChange={close}
      title={title}
      description={description}
      footer={
        <>
          <Button onClick={() => close(false)}>Cancel</Button>
          <Button
            variant={danger ? "danger" : "primary"}
            disabled={typed !== name}
            busy={busy}
            onClick={async () => {
              setBusy(true);
              setError(null);
              try {
                await onConfirm();
                close(false);
              } catch (err) {
                setError(err);
              } finally {
                setBusy(false);
              }
            }}
          >
            {action}
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
        }}
      >
        <TextField
          label={
            <>
              Type <span className="mono">{name}</span> to confirm
            </>
          }
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          mono
        />
      </form>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}

/** A simple confirmation without typing, for reversible actions. */
export function Confirm({
  open,
  onOpenChange,
  title,
  description,
  action,
  onConfirm,
}: {
  open: boolean;
  onOpenChange(o: boolean): void;
  title: string;
  description: ReactNode;
  action: string;
  onConfirm(): Promise<void> | void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal
      open={open}
      onOpenChange={(o) => {
        if (!o) setError(null);
        onOpenChange(o);
      }}
      title={title}
      description={description}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            variant="primary"
            busy={busy}
            onClick={async () => {
              setBusy(true);
              setError(null);
              try {
                await onConfirm();
                onOpenChange(false);
              } catch (err) {
                setError(errorMessage(err));
              } finally {
                setBusy(false);
              }
            }}
          >
            {action}
          </Button>
        </>
      }
    >
      {error && (
        <div className="notice notice-crit" role="alert">
          {error}
        </div>
      )}
    </Modal>
  );
}
