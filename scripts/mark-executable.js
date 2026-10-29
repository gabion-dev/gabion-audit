// scripts/mark-executable.js
// Marks the compiled command-line entries as executable. tsc emits them
// with the default file mode, and a bin that is linked from a workspace
// is executed straight from dist/ — without the executable bit the shell
// would interpret the JavaScript as a shell script. A published tarball
// gets the bit from npm on install; a workspace link does not.

import { chmodSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const cliDir = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "cli");
for (const entry of readdirSync(cliDir)) {
  if (entry.endsWith(".js")) {
    chmodSync(join(cliDir, entry), 0o755);
  }
}
