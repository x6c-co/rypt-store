// Latin and Latin Extended subsets only, bundled into the binary (core X10).
import "@fontsource/libre-franklin/latin-400.css";
import "@fontsource/libre-franklin/latin-ext-400.css";
import "@fontsource/libre-franklin/latin-500.css";
import "@fontsource/libre-franklin/latin-ext-500.css";
import "@fontsource/libre-franklin/latin-600.css";
import "@fontsource/libre-franklin/latin-ext-600.css";
import "@fontsource/libre-franklin/latin-700.css";
import "@fontsource/libre-franklin/latin-ext-700.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-ext-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "@fontsource/ibm-plex-mono/latin-ext-500.css";
import "./styles/tokens.css";
import "./styles/app.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App, makeQueryClient } from "./App";
import { applyTheme, getThemePreference } from "./lib/theme";

// The theme is applied from the bundle, not an inline script: the server's
// CSP (default-src 'self') forbids inline scripts.
applyTheme(getThemePreference());

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App client={makeQueryClient()} />
  </StrictMode>,
);
