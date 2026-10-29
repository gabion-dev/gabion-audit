// src/inventory/rust-toolchain.ts
/**
 * The Rust release a repository pins in rust-toolchain.toml. A channel
 * name (`stable`) pins nothing and is not judged; a channel that is
 * neither a channel name nor a release number is an error.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { DependencyUse } from "../types.js";

const CHANNEL = /^\s*channel\s*=\s*"([^"]+)"/m;
const CHANNEL_NAMES: ReadonlySet<string> = new Set(["stable", "beta", "nightly"]);

export function rustToolchainUses(root: string): DependencyUse[] {
  const site = "rust-toolchain.toml";
  const path = join(root, site);
  if (!existsSync(path)) return [];
  const channel = CHANNEL.exec(readFileSync(path, "utf-8"))?.[1];
  if (channel === undefined) throw new Error(`${site}: no channel = "…"`);
  if (CHANNEL_NAMES.has(channel)) return [];
  if (!/^\d+\.\d+(\.\d+)?$/.test(channel)) {
    throw new Error(`${site}: channel "${channel}" is neither a channel name nor a release number`);
  }
  return [{ source: "rust", name: "rust", version: channel, site }];
}
