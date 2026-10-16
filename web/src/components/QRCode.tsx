import qrcode from "qrcode-generator";
import { useMemo } from "react";

/**
 * Renders a QR code as inline SVG elements. The server's CSP forbids data:
 * and blob: images, so the code is never an <img>.
 */
export function QRCode({ value, label }: { value: string; label: string }) {
  const { size, path } = useMemo(() => {
    const qr = qrcode(0, "M");
    qr.addData(value);
    qr.make();
    const n = qr.getModuleCount();
    let d = "";
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) d += `M${c} ${r}h1v1h-1z`;
      }
    }
    return { size: n, path: d };
  }, [value]);
  return (
    <svg className="qr" viewBox={`-2 -2 ${size + 4} ${size + 4}`} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect x={-2} y={-2} width={size + 4} height={size + 4} fill="#ffffff" />
      <path d={path} fill="#000000" />
    </svg>
  );
}
