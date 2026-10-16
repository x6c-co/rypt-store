import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";

interface ToastItem {
  id: number;
  text: string;
  error: boolean;
}

interface ToastApi {
  show(text: string): void;
  error(text: string): void;
}

const ToastContext = createContext<ToastApi>({ show() {}, error() {} });

/** Toasts confirm actions with the same verb as the button (core 14.4). */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const next = useRef(1);

  const push = useCallback((text: string, error: boolean) => {
    const id = next.current++;
    setItems((xs) => [...xs.slice(-3), { id, text, error }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), error ? 8000 : 4000);
  }, []);

  const api = useMemo<ToastApi>(() => ({ show: (t) => push(t, false), error: (t) => push(t, true) }), [push]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toasts" aria-live="polite" aria-atomic="false">
        {items.map((t) => (
          <div key={t.id} className={`toast${t.error ? " error" : ""}`} role={t.error ? "alert" : "status"}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  return useContext(ToastContext);
}
