// src/inventory/github-actions.ts
/**
 * GitHub Actions: every action a workflow or a composite action of the
 * repository uses, by the reference it is pinned to.
 *
 * A reference by major tag (`@v7`) fixes a line: the action follows every
 * release of it, and the use is current while the newest release lies on
 * that line. A reference by full version fixes a release. Any other
 * reference — a commit, a branch — is an error naming the site: the audit
 * cannot tell which release it is.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { DependencyUse } from "../types.js";
import { lineAt, trackedFiles } from "./git.js";

const USES = /^\s*(?:-\s+)?uses:\s*["']?([^\s"'#]+)["']?/gm;
const VERSION_REFERENCE = /^v?(\d+(?:\.\d+)*)$/;

export function githubActionUses(root: string): DependencyUse[] {
  const files = trackedFiles(root, [
    ":(glob).github/workflows/*.yml",
    ":(glob).github/workflows/*.yaml",
    ":(glob).github/actions/**/action.yml",
    ":(glob).github/actions/**/action.yaml",
  ]);
  const uses: DependencyUse[] = [];
  for (const file of files) {
    const text = readFileSync(join(root, file), "utf-8");
    for (const match of text.matchAll(USES)) {
      const target = match[1];
      if (target === undefined || target.startsWith("./") || target.startsWith("docker://")) continue;
      const site = `${file}:${String(lineAt(text, match.index))}`;
      const at = target.lastIndexOf("@");
      const path = at === -1 ? target : target.slice(0, at);
      const reference = at === -1 ? "" : target.slice(at + 1);
      const [owner, repository] = path.split("/");
      if (owner === undefined || repository === undefined) {
        throw new Error(`${site}: "${target}" names no owner/repository`);
      }
      const version = VERSION_REFERENCE.exec(reference)?.[1];
      if (version === undefined) {
        throw new Error(
          `${site}: ${path} is pinned to "${reference}" — not a version tag, so the audit cannot tell which release it is`,
        );
      }
      uses.push({
        source: "github-action",
        name: `${owner}/${repository}`,
        version,
        site,
        precision: version.split(".").length < 3 ? "line" : "release",
      });
    }
  }
  return uses;
}
