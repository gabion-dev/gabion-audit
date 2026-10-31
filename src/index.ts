// src/index.ts
/**
 * The audit as a library: a repository that prepares an npm tree in its
 * own code (a delivered lock file written to a scratch directory), judges
 * a policy of its own, or scanned its compositions for vulnerabilities
 * calls `audit` with those, and everything the audit file names is judged
 * with them under one report.
 */

export { audit, EXIT_CODE, report, SourceUnavailable, type AuditOptions, type AuditResult } from "./audit.js";
export { readOsvScannerReport, type OsvScannerSource } from "./osv-scanner.js";
export { judgeVulnerabilities, vulnerabilitySection } from "./vulnerabilities.js";
export { CONFIG_FILE, parseConfig, readConfig, type AuditConfig, type ConfiguredAdvisoryTree } from "./config.js";
export type * from "./types.js";
