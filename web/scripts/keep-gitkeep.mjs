// vite build empties web/dist; the Go embed (web/embed.go) needs the
// directory to exist in a fresh checkout, so recreate its .gitkeep.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

writeFileSync(fileURLToPath(new URL("../dist/.gitkeep", import.meta.url)), "");
