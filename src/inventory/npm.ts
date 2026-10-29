// src/inventory/npm.ts
/**
 * npm: the direct dependencies of every workspace the root lock file
 * records, at the release the lock file resolves for each.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { isRecord } from "../sources.js";
import type { DependencyUse } from "../types.js";
import { trackedFiles } from "./git.js";

const NPM_DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

// ==========================================
// npm
// ==========================================

/**
 * Direct dependencies of every workspace the root lock file records, at
 * the release npm resolves for each: the workspace's own node_modules
 * first, then the root's — the order Node resolves a require in. A
 * dependency resolved to a link is a workspace of this repository, not a
 * registry release, and is not judged here.
 */
export function npmUses(repoRoot: string): DependencyUse[] {
  const lockfilePath = join(repoRoot, "package-lock.json");
  if (!existsSync(lockfilePath)) {
    for (const manifestPath of trackedFiles(repoRoot, [":(glob)**/package.json"])) {
      const manifest: unknown = JSON.parse(readFileSync(join(repoRoot, manifestPath), "utf-8"));
      if (NPM_DEPENDENCY_FIELDS.some((field) => isRecord(manifest) && isRecord(manifest[field]) && Object.keys(manifest[field]).length > 0)) {
        throw new Error(`${manifestPath} declares dependencies and the repository has no package-lock.json: no lock file fixes their releases`);
      }
    }
    return [];
  }
  const lockfile: unknown = JSON.parse(readFileSync(lockfilePath, "utf-8"));
  const packages = isRecord(lockfile) ? lockfile["packages"] : undefined;
  if (!isRecord(packages)) {
    throw new Error(`${lockfilePath} carries no "packages" map`);
  }

  const uses: DependencyUse[] = [];
  const workspaces = Object.entries(packages).filter(
    ([location]) => !location.split("/").includes("node_modules"),
  );
  for (const [workspace, entry] of workspaces) {
    if (!isRecord(entry)) continue;
    const site = workspace === "" ? "package.json" : `${workspace}/package.json`;
    for (const field of NPM_DEPENDENCY_FIELDS) {
      const declared = entry[field];
      if (!isRecord(declared)) continue;
      for (const [name, range] of Object.entries(declared)) {
        const candidates = [
          ...(workspace === "" ? [] : [`${workspace}/node_modules/${name}`]),
          `node_modules/${name}`,
        ];
        const location = candidates.find((candidate) => isRecord(packages[candidate]));
        const resolved = location === undefined ? undefined : packages[location];
        if (!isRecord(resolved)) {
          throw new Error(
            `${site} declares ${name} (${String(range)}), and ${lockfilePath} resolves it nowhere — ` +
              "run npm install so the lock file covers the manifest",
          );
        }
        if (resolved["link"] === true) continue;
        const version = resolved["version"];
        if (typeof version !== "string") {
          throw new Error(`${lockfilePath}: ${String(location)} carries no version`);
        }
        uses.push({
          source: "npm",
          name,
          version,
          ...(typeof range === "string" ? { declared: range } : {}),
          site,
        });
      }
    }
  }

  // A package manifest outside the workspaces is installed by nobody this
  // lock file describes; one with dependencies would be judged by nothing.
  const workspaceManifests = new Set(
    workspaces.map(([workspace]) => (workspace === "" ? "package.json" : `${workspace}/package.json`)),
  );
  for (const manifestPath of trackedFiles(repoRoot, [":(glob)**/package.json"])) {
    if (workspaceManifests.has(manifestPath)) continue;
    const manifest: unknown = JSON.parse(readFileSync(join(repoRoot, manifestPath), "utf-8"));
    const declaring = NPM_DEPENDENCY_FIELDS.filter(
      (field) => isRecord(manifest) && isRecord(manifest[field]) && Object.keys(manifest[field]).length > 0,
    );
    if (declaring.length > 0) {
      throw new Error(
        `${manifestPath} declares ${declaring.join(", ")} but is not a workspace of ${lockfilePath}: ` +
          "its releases are fixed by no lock file the audit reads — make it a workspace, or audit it with its own lock file",
      );
    }
  }
  return uses;
}
