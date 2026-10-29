// src/inventory/pins.ts
/**
 * Releases pinned in files no manifest describes — a version variable in a
 * build script — as the repository's audit file declares them. Each named
 * file must hold the pin exactly once: a pattern that finds nothing means
 * the pin moved or was renamed, and a pin judged by nothing reads like a
 * current one.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Pin } from "../config.js";
import type { DependencyUse } from "../types.js";
import { lineAt } from "./git.js";

export function pinUses(root: string, pins: readonly Pin[]): DependencyUse[] {
  const uses: DependencyUse[] = [];
  for (const pin of pins) {
    const pattern = new RegExp(pin.pattern, "gm");
    for (const file of pin.files) {
      const text = readFileSync(join(root, file), "utf-8");
      const matches = [...text.matchAll(pattern)];
      if (matches.length !== 1) {
        throw new Error(
          `${file}: the pin of ${pin.name} (/${pin.pattern}/) matches ${String(matches.length)} times, not once — fix the pattern in the audit file`,
        );
      }
      const [match] = matches;
      const version = match?.[1];
      if (match === undefined || version === undefined) {
        throw new Error(`${file}: the pattern of ${pin.name} has no capture group for the version`);
      }
      uses.push({ source: "pin", name: pin.name, version, site: `${file}:${String(lineAt(text, match.index))}` });
    }
  }
  return uses;
}
