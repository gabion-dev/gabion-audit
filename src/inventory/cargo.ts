// src/inventory/cargo.ts
/**
 * Cargo: the direct dependencies of every workspace member, at the release
 * Cargo.lock resolves for each — normal, development and build ones alike,
 * since each is a release the repository builds with. The resolution is
 * Cargo's own (`cargo metadata --locked`), not a reading of the manifests:
 * renamed dependencies, workspace inheritance and features are Cargo's to
 * interpret.
 *
 * A dependency from anywhere but crates.io — a git repository, another
 * registry — is an error: no source here can say which release is newest.
 * Path dependencies are crates of the repository itself.
 */

import { existsSync } from "node:fs";
import { join, relative } from "node:path";
import { isRecord } from "../sources.js";
import type { DependencyUse } from "../types.js";
import { run } from "./git.js";

const CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index";

export function cargoUses(root: string): DependencyUse[] {
  if (!existsSync(join(root, "Cargo.toml"))) return [];
  if (!existsSync(join(root, "Cargo.lock"))) {
    throw new Error("Cargo.toml without Cargo.lock: no lock file fixes the releases of its dependencies");
  }
  const metadata: unknown = JSON.parse(run("cargo", ["metadata", "--format-version", "1", "--locked"], root));
  if (!isRecord(metadata)) throw new Error("cargo metadata answered no document");
  const packages = Array.isArray(metadata["packages"]) ? metadata["packages"].filter(isRecord) : [];
  const members = new Set(Array.isArray(metadata["workspace_members"]) ? metadata["workspace_members"] : []);
  const resolve = isRecord(metadata["resolve"]) ? metadata["resolve"] : undefined;
  const nodes = resolve !== undefined && Array.isArray(resolve["nodes"]) ? resolve["nodes"].filter(isRecord) : [];
  const packageById = new Map(packages.map((entry) => [entry["id"], entry]));

  const uses: DependencyUse[] = [];
  for (const node of nodes) {
    if (!members.has(node["id"])) continue;
    const member = packageById.get(node["id"]);
    const manifest = typeof member?.["manifest_path"] === "string" ? member["manifest_path"] : undefined;
    if (member === undefined || manifest === undefined) continue;
    const site = relative(root, manifest);
    const declared = Array.isArray(member["dependencies"]) ? member["dependencies"].filter(isRecord) : [];
    for (const dependency of Array.isArray(node["deps"]) ? node["deps"].filter(isRecord) : []) {
      const resolved = packageById.get(dependency["pkg"]);
      if (resolved === undefined) continue;
      const source = resolved["source"];
      if (source === null || source === undefined) continue; // a crate of this workspace
      const name = String(resolved["name"]);
      if (source !== CRATES_IO) {
        throw new Error(`${site}: ${name} comes from ${String(source)}, not crates.io — no source here can say which release of it is newest`);
      }
      const requirement = declared.find(
        (entry) => entry["name"] === name || entry["rename"] === dependency["name"],
      )?.["req"];
      uses.push({
        source: "crates",
        name,
        version: String(resolved["version"]),
        site,
        ...(typeof requirement === "string" ? { declared: requirement } : {}),
      });
    }
  }
  return uses;
}
