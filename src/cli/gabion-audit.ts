#!/usr/bin/env node
// src/cli/gabion-audit.ts
/**
 * gabion-audit — audit the repository in the current directory, or in the
 * directory given as the first argument, by its gabion-audit.json.
 *
 *   gabion-audit [repository directory] [--osv-report <file>=<scope>]...
 *
 * An --osv-report names the JSON report of a vulnerability scan
 * (OSV-Scanner, `--format json`) and the scope its findings belong to —
 * the name a declaration in gabion-audit.json carries (production,
 * development, cargo, …). One report per scope: a repository that judges
 * two compositions scans them into two reports. The reports are judged
 * together with the advisory trees the file names, under one verdict.
 *
 * Exit codes: 0 — nothing undeclared; 1 — something undeclared or dead,
 * or nothing to judge; 2 — something could not be judged.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { audit, EXIT_CODE } from "../audit.js";
import { readOsvScannerReport } from "../osv-scanner.js";
import type { JudgedVulnerabilities, ReportedVulnerability } from "../types.js";

const USAGE = "usage: gabion-audit [repository directory] [--osv-report <file>=<scope>]...";

const args = process.argv.slice(2);
let root: string | undefined;
const reports: { file: string; scope: string }[] = [];
for (let index = 0; index < args.length; index++) {
  const arg = args[index] ?? "";
  if (arg === "--osv-report") {
    const value = args[index + 1] ?? "";
    const equals = value.lastIndexOf("=");
    if (equals <= 0 || equals === value.length - 1) {
      console.error(`${USAGE}\n--osv-report needs <file>=<scope>, got "${value}"`);
      process.exit(2);
    }
    reports.push({ file: value.slice(0, equals), scope: value.slice(equals + 1) });
    index++;
  } else if (arg.startsWith("-") || root !== undefined) {
    console.error(USAGE);
    process.exit(2);
  } else {
    root = arg;
  }
}

let vulnerabilities: JudgedVulnerabilities | undefined;
if (reports.length > 0) {
  const reported: ReportedVulnerability[] = [];
  for (const report of reports) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(report.file, "utf-8"));
    } catch (error) {
      console.error(`gabion-audit: ${report.file} could not be read: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(2);
    }
    try {
      reported.push(...readOsvScannerReport(parsed, () => report.scope));
    } catch (error) {
      console.error(`gabion-audit: ${report.file} is not an OSV-Scanner JSON report: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(2);
    }
  }
  vulnerabilities = { reported, judgedScopes: [...new Set(reports.map((report) => report.scope))] };
}

const result = await audit({ root: resolve(root ?? "."), ...(vulnerabilities === undefined ? {} : { vulnerabilities }) });
console.log(result.text);
process.exit(EXIT_CODE[result.verdict]);
