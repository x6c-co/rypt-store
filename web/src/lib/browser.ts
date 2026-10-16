/** Copies text to the clipboard. */
export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.className = "visually-hidden";
  document.body.appendChild(ta);
  ta.select();
  try {
    if (!document.execCommand("copy")) throw new Error("Copy is not available in this browser.");
  } finally {
    ta.remove();
  }
}

/** Offers text as a file download. */
export function downloadText(filename: string, text: string, type = "text/plain"): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Downloads a response body under a file name. */
export async function downloadResponse(filename: string, response: Response): Promise<void> {
  const text = await response.text();
  downloadText(filename, text, response.headers.get("Content-Type") ?? "text/plain");
}
