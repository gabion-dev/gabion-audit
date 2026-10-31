// src/osv-scanner.ts
/**
 * The JSON report of OSV-Scanner (`--format json`), read into reported
 * vulnerabilities: one per component and bulletin, where a bulletin is
 * the group the scanner forms of a record and its aliases — a GHSA and the
 * CVE it mirrors are one bulletin, counted and declared once.
 *
 * The scope of each finding is the caller's: it maps every scanned source
 * (the file the component was read from) to the scope it judges, so the
 * same bulletin in a production composition and in a development one are
 * two findings with two fates.
 */

import type { ReportedVulnerability } from "./types.js";

class ReportShapeError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function field(value: Record<string, unknown>, key: string, path: string): string {
  const entry = value[key];
  if (typeof entry !== "string") throw new ReportShapeError(`${path}.${key}: expected a string`);
  return entry;
}

/** A scanned source as the report names it. */
export interface OsvScannerSource {
  readonly path: string;
  readonly type: string;
}

/** The releases a bulletin names as fixed for the given package, every range. */
function fixedVersions(vulnerability: Record<string, unknown>, packageName: string): string[] {
  const fixed = new Set<string>();
  for (const affected of Array.isArray(vulnerability["affected"]) ? vulnerability["affected"] : []) {
    if (!isRecord(affected)) continue;
    const pkg = affected["package"];
    if (isRecord(pkg) && typeof pkg["name"] === "string" && pkg["name"] !== packageName) continue;
    for (const range of Array.isArray(affected["ranges"]) ? affected["ranges"] : []) {
      if (!isRecord(range)) continue;
      for (const event of Array.isArray(range["events"]) ? range["events"] : []) {
        if (isRecord(event) && typeof event["fixed"] === "string") fixed.add(event["fixed"]);
      }
    }
  }
  return [...fixed];
}

/** A GHSA when the bulletin has one — the identifier most advisories are known by — else its first identifier. */
function leadingIdentifier(identifiers: readonly string[]): string {
  return identifiers.find((id) => id.startsWith("GHSA-")) ?? identifiers[0] ?? "";
}

/**
 * Reads a parsed OSV-Scanner JSON report. `scopeOf` names the scope of
 * each scanned source; a source the caller does not expect is for the
 * caller to refuse there. Throws when the report is not of the shape the
 * scanner writes — a report that cannot be read judged nothing.
 */
export function readOsvScannerReport(
  parsed: unknown,
  scopeOf: (source: OsvScannerSource) => string,
): ReportedVulnerability[] {
  if (!isRecord(parsed) || !Array.isArray(parsed["results"])) {
    throw new ReportShapeError("(root).results: expected the results array of an OSV-Scanner JSON report");
  }
  const reported: ReportedVulnerability[] = [];
  parsed["results"].forEach((result: unknown, resultIndex: number) => {
    const resultPath = `results[${String(resultIndex)}]`;
    if (!isRecord(result) || !isRecord(result["source"])) throw new ReportShapeError(`${resultPath}.source: expected an object`);
    const source: OsvScannerSource = {
      path: field(result["source"], "path", `${resultPath}.source`),
      type: field(result["source"], "type", `${resultPath}.source`),
    };
    const scope = scopeOf(source);
    const packages = Array.isArray(result["packages"]) ? result["packages"] : [];
    packages.forEach((entry: unknown, packageIndex: number) => {
      const packagePath = `${resultPath}.packages[${String(packageIndex)}]`;
      if (!isRecord(entry) || !isRecord(entry["package"])) throw new ReportShapeError(`${packagePath}.package: expected an object`);
      const pkg = entry["package"];
      const name = field(pkg, "name", `${packagePath}.package`);
      const version = field(pkg, "version", `${packagePath}.package`);
      const ecosystem = field(pkg, "ecosystem", `${packagePath}.package`);
      const purl = field(pkg, "purl", `${packagePath}.package`);
      const vulnerabilities = (Array.isArray(entry["vulnerabilities"]) ? entry["vulnerabilities"] : []).filter(isRecord);
      const byId = new Map<string, Record<string, unknown>>();
      for (const vulnerability of vulnerabilities) {
        if (typeof vulnerability["id"] === "string") byId.set(vulnerability["id"], vulnerability);
      }
      // The scanner groups a record with its aliases; a package with
      // vulnerabilities but no groups is not the scanner's shape.
      const groups = (Array.isArray(entry["groups"]) ? entry["groups"] : []).filter(isRecord);
      if (vulnerabilities.length > 0 && groups.length === 0) {
        throw new ReportShapeError(`${packagePath}.groups: expected the bulletin groups of the package`);
      }
      for (const group of groups) {
        const ids = strings(group["ids"]);
        const aliases = strings(group["aliases"]);
        const identifiers = [...new Set([...ids, ...aliases])];
        const records = ids.map((id) => byId.get(id)).filter((record): record is Record<string, unknown> => record !== undefined);
        const summary = records.map((record) => record["summary"]).find((value): value is string => typeof value === "string") ?? "";
        const severity = typeof group["max_severity"] === "string" ? group["max_severity"] : "";
        reported.push({
          scope,
          purl,
          name,
          version,
          ecosystem,
          source: source.path,
          advisory: leadingIdentifier(identifiers),
          identifiers,
          summary,
          severity,
          fixedVersions: [...new Set(records.flatMap((record) => fixedVersions(record, name)))],
        });
      }
    });
  });
  return reported;
}
