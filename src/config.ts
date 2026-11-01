// src/config.ts
/**
 * The audit's file in a repository, `gabion-audit.json` at its root: the
 * npm trees whose advisories are judged, the advisories it keeps on
 * purpose, and the vulnerabilities a scan of its compositions reports
 * that it keeps on purpose — each with its reason and the event that ends
 * it.
 *
 * Plain JSON, so a repository of any language can carry it. Its shape is
 * checked before anything is judged: a misspelled field would otherwise
 * read as "nothing declared" and turn a kept advisory into a refusal, or a
 * tree into nothing judged at all. The check is written by hand rather
 * than with a schema library: the file has three kinds of entry, and the
 * package then needs nothing at run time — a repository runs it with
 * `npx` before its release, and every dependency it pulled in would be
 * resolved fresh on that machine, outside the lock file of any repository.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { reviewDate } from "./review.js";
import type { AcceptedAdvisory, AcceptedVulnerability } from "./types.js";

export const CONFIG_FILE = "gabion-audit.json";

/** An npm tree as the audit file names it: a directory of the repository. */
export interface ConfiguredAdvisoryTree {
  readonly name: string;
  readonly directory: string;
  readonly args: readonly string[];
}

export interface AuditConfig {
  readonly advisoryTrees: readonly ConfiguredAdvisoryTree[];
  readonly acceptedAdvisories: readonly AcceptedAdvisory[];
  readonly acceptedVulnerabilities: readonly AcceptedVulnerability[];
}

/**
 * Fields the file carried while the audit judged freshness too. Named
 * here so a file left over from that time is refused with where the
 * concern went, not with "unknown field".
 */
const RETIRED_FIELDS: ReadonlySet<string> = new Set(["pins", "acceptedLags"]);

class ShapeError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ShapeError(`${path}: expected a non-empty string`);
  }
  return value;
}

/** The event that ends a reason: words, or a date that is a date (review.ts). */
function reviewEvent(value: unknown, path: string): string {
  const event = text(value, path);
  try {
    reviewDate(event);
  } catch (error) {
    throw new ShapeError(`${path}: ${error instanceof Error ? error.message : String(error)} — write a real date (2026-12-01) or the event in words`);
  }
  return event;
}

function record(value: unknown, path: string, fields: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) throw new ShapeError(`${path}: expected an object`);
  for (const key of Object.keys(value)) {
    if (!fields.includes(key)) {
      throw new ShapeError(`${path}.${key}: unknown field (expected ${fields.join(", ")})`);
    }
  }
  return value;
}

function list<T>(value: unknown, path: string, item: (entry: unknown, path: string) => T): T[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new ShapeError(`${path}: expected an array`);
  return value.map((entry, index) => item(entry, `${path}[${String(index)}]`));
}

function advisoryTree(value: unknown, path: string): ConfiguredAdvisoryTree {
  const entry = record(value, path, ["name", "directory", "args"]);
  return {
    name: text(entry["name"], `${path}.name`),
    directory: text(entry["directory"], `${path}.directory`),
    args: list(entry["args"], `${path}.args`, text),
  };
}

function acceptedAdvisory(value: unknown, path: string): AcceptedAdvisory {
  const entry = record(value, path, ["tree", "package", "advisory", "reason", "reviewWhen"]);
  return {
    tree: text(entry["tree"], `${path}.tree`),
    package: text(entry["package"], `${path}.package`),
    advisory: text(entry["advisory"], `${path}.advisory`),
    reason: text(entry["reason"], `${path}.reason`),
    reviewWhen: reviewEvent(entry["reviewWhen"], `${path}.reviewWhen`),
  };
}

function acceptedVulnerability(value: unknown, path: string): AcceptedVulnerability {
  const entry = record(value, path, ["scope", "purl", "advisory", "reason", "reviewWhen"]);
  const purl = text(entry["purl"], `${path}.purl`);
  if (!purl.startsWith("pkg:") || !purl.includes("@")) {
    throw new ShapeError(`${path}.purl: expected a package URL with its version (pkg:<type>/<name>@<version>)`);
  }
  return {
    scope: text(entry["scope"], `${path}.scope`),
    purl,
    advisory: text(entry["advisory"], `${path}.advisory`),
    reason: text(entry["reason"], `${path}.reason`),
    reviewWhen: reviewEvent(entry["reviewWhen"], `${path}.reviewWhen`),
  };
}

/** The configuration read from already-parsed JSON; throws naming the field that is wrong. */
export function parseConfig(parsed: unknown): AuditConfig {
  if (isRecord(parsed)) {
    const retired = Object.keys(parsed).find((key) => RETIRED_FIELDS.has(key));
    if (retired !== undefined) {
      throw new ShapeError(
        `${retired}: the audit no longer judges freshness — Renovate proposes updates and holds a lag by a package rule in its configuration; remove the field`,
      );
    }
  }
  const root = record(parsed, "(root)", ["$schema", "advisoryTrees", "acceptedAdvisories", "acceptedVulnerabilities"]);
  if (root["$schema"] !== undefined) text(root["$schema"], "$schema");
  return {
    advisoryTrees: list(root["advisoryTrees"], "advisoryTrees", advisoryTree),
    acceptedAdvisories: list(root["acceptedAdvisories"], "acceptedAdvisories", acceptedAdvisory),
    acceptedVulnerabilities: list(root["acceptedVulnerabilities"], "acceptedVulnerabilities", acceptedVulnerability),
  };
}

/** The repository's audit file, checked; an empty configuration where it has none. */
export function readConfig(root: string): AuditConfig {
  const path = join(root, CONFIG_FILE);
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { advisoryTrees: [], acceptedAdvisories: [], acceptedVulnerabilities: [] };
    }
    throw error;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`${CONFIG_FILE}: not JSON (${error instanceof Error ? error.message : String(error)})`);
  }
  try {
    return parseConfig(parsed);
  } catch (error) {
    if (error instanceof ShapeError) throw new Error(`${CONFIG_FILE}: ${error.message}`);
    throw error;
  }
}
