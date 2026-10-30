#!/usr/bin/env node
// src/cli/gabion-audit.ts
/**
 * gabion-audit — audit the repository in the current directory, or in the
 * directory given as the only argument, by its gabion-audit.json.
 *
 * Exit codes: 0 — nothing undeclared; 1 — something undeclared or dead,
 * or nothing to judge; 2 — something could not be judged.
 */

import { resolve } from "node:path";
import { audit, EXIT_CODE } from "../audit.js";

const args = process.argv.slice(2);
if (args.length > 1 || args.some((arg) => arg.startsWith("-"))) {
  console.error("usage: gabion-audit [repository directory]");
  process.exit(2);
}
const result = await audit({ root: resolve(args[0] ?? ".") });
console.log(result.text);
process.exit(EXIT_CODE[result.verdict]);
