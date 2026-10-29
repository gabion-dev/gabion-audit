// scripts/clean-dist.js
// Removes dist/ before compiling. tsc only adds and overwrites files, so
// an entry that moved (a library module that became a CLI entry, or the
// reverse) would leave its old compiled file behind — and a stale bin
// link could keep resolving to it. A build that starts from nothing
// cannot ship a file the sources no longer describe.

import { rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

rmSync(join(dirname(fileURLToPath(import.meta.url)), "..", "dist"), {
  recursive: true,
  force: true,
});
