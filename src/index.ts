// src/index.ts
/**
 * The audit as a library: a repository that inventories some of its pins
 * in its own code (a constants file, a manifest of its own format) or
 * judges a policy of its own calls `audit` with those, and everything the
 * package finds by itself is judged with them under one report.
 */

export { audit, EXIT_CODE, report, type AuditOptions, type AuditResult } from "./audit.js";
export { CONFIG_FILE, readConfig, type AuditConfig } from "./config.js";
export {
  currentRelease,
  fetchJson,
  fetchText,
  githubReleaseCatalog,
  githubTagCatalog,
  listingCatalog,
  SourceUnavailable,
} from "./sources.js";
export type * from "./types.js";
export { compareVersions, isOnLine, isPreRelease, lineOf, newestOf } from "./versions.js";
