import { copyText, downloadText } from "../lib/browser";
import { useToast } from "./Toast";
import { Button, Notice } from "./ui";

/** Shows recovery codes once, with copy and download. */
export function RecoveryCodes({ codes }: { codes: string[] }) {
  const toast = useToast();
  if (codes.length === 0) return null;
  const text = codes.join("\n") + "\n";
  return (
    <div className="stack-sm">
      <Notice tone="brass">
        These recovery codes are shown once. Each one signs you in a single time if you lose your authenticator. Store them somewhere safe.
      </Notice>
      <ul className="codes" aria-label="Recovery codes" data-testid="recovery-codes">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="row">
        <Button
          size="sm"
          onClick={async () => {
            await copyText(text);
            toast.show("Copied recovery codes.");
          }}
        >
          Copy codes
        </Button>
        <Button size="sm" onClick={() => downloadText("rypt-store-recovery-codes.txt", text)}>
          Download codes
        </Button>
      </div>
    </div>
  );
}
