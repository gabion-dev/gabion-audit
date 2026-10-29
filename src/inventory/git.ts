// src/inventory/git.ts
/**
 * The files the inventory reads are the tracked ones: an untracked build
 * leftover or a dependency directory is not what the repository fixes.
 */

import { spawnSync } from "node:child_process";

/** Run a program from an argument vector (no shell) and return its output, or throw with its reason. */
export function run(command: string, args: readonly string[], cwd: string): string {
  const result = spawnSync(command, [...args], { cwd, encoding: "utf-8", maxBuffer: 256 * 1024 * 1024 });
  if (result.error !== undefined) {
    throw new Error(`${command} ${args.join(" ")}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const why = result.signal !== null ? `signal ${result.signal}` : `exit code ${String(result.status)}`;
    throw new Error(`${command} ${args.join(" ")} failed (${why})\n${result.stderr}`);
  }
  return result.stdout;
}

/** Tracked files matching git pathspecs, relative to the repository root. */
export function trackedFiles(root: string, pathspecs: readonly string[]): readonly string[] {
  return run("git", ["ls-files", "-z", "--", ...pathspecs], root)
    .split("\0")
    .filter((path) => path !== "");
}

/** The line of `offset` in `text`, for an error that names its site. */
export function lineAt(text: string, offset: number): number {
  return text.slice(0, offset).split("\n").length;
}
