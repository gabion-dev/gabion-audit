// src/audit.ts
/**
 * The audit of one repository: the advisories in the npm trees it names,
 * the vulnerabilities a scan of its compositions reported (judged when
 * the caller passes them, against the declarations of the audit file),
 * and any section the caller judged itself.
 *
 * Only what is undeclared is red. An advisory kept on purpose is declared
 * in the audit file with its reason and the event that ends it; a
 * declaration that matches nothing any more is red as well, so an excuse
 * cannot outlive its cause and cover the next advisory unjudged.
 *
 * Whether a dependency is current is not judged here: Renovate proposes
 * each newer release as a pull request, and a lag kept on purpose is a
 * package rule of its configuration. The audit gates a release on what a
 * bot cannot decide for the repository — a known vulnerability in the tree
 * a consumer installs.
 *
 * Verdicts: passed — nothing undeclared; refused — an undeclared advisory,
 * a dead declaration, an audit file that cannot be read, or nothing to
 * judge at all; unable — something could not be judged (npm audit failed).
 * A refusal outranks an inability.
 */

import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { CONFIG_FILE, readConfig, type AuditConfig } from "./config.js";
import type { AcceptedAdvisory, AdvisoryTree, Finding, JudgedVulnerabilities, Section, Verdict } from "./types.js";
import { vulnerabilitySection } from "./vulnerabilities.js";

export interface AuditOptions {
  /** The repository root: the audit file and its trees are read relative to it. */
  readonly root: string;
  /** The audit file, already read; read from `root` when absent. */
  readonly config?: AuditConfig;
  /** npm trees the caller prepares itself, judged with those of the audit file. */
  readonly advisoryTrees?: readonly AdvisoryTree[];
  /** Sections the caller judged itself (a policy of its own), reported first. */
  readonly sections?: readonly Section[];
  /**
   * What a vulnerability scan of the repository's compositions reported,
   * with every scope the scan covered. Judged against the file's
   * acceptedVulnerabilities; absent, those declarations are left to the
   * run that judges their scopes.
   */
  readonly vulnerabilities?: JudgedVulnerabilities;
}

export interface AuditResult {
  readonly sections: readonly Section[];
  readonly verdict: Verdict;
  readonly text: string;
}

/** Something that could not be read; the report names it as the reason a judgement is missing. */
export class SourceUnavailable extends Error {}

const errorText = (error: unknown): string => (error instanceof Error ? error.message : String(error));

// ==========================================
// Advisories
// ==========================================

interface ReportedAdvisory {
  readonly tree: string;
  readonly package: string;
  readonly advisory: string;
  readonly severity: string;
  readonly title: string;
}

/**
 * The advisories `npm audit --json` reports in `cwd`, one per package and
 * advisory. A package listed only as an effect of another package's
 * advisory carries no advisory of its own and is not repeated.
 */
function auditTree(tree: string, cwd: string, args: readonly string[]): ReportedAdvisory[] {
  const result = spawnSync("npm", ["audit", "--json", ...args], { cwd, encoding: "utf-8", maxBuffer: 256 * 1024 * 1024 });
  if (result.error !== undefined) {
    throw new SourceUnavailable(`npm audit in ${cwd}: ${result.error.message}`);
  }
  // npm audit exits non-zero whenever it reports anything; the JSON on
  // stdout is the answer, and its absence or an "error" member is the
  // failure.
  let report: unknown;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    throw new SourceUnavailable(`npm audit in ${cwd}: exit code ${String(result.status)}\n${result.stderr}`);
  }
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new SourceUnavailable(`npm audit in ${cwd} answered no report`);
  }
  const { error, vulnerabilities } = report as { error?: unknown; vulnerabilities?: unknown };
  if (error !== undefined) throw new SourceUnavailable(`npm audit in ${cwd}: ${JSON.stringify(error)}`);
  if (typeof vulnerabilities !== "object" || vulnerabilities === null) {
    throw new SourceUnavailable(`npm audit in ${cwd} answered no "vulnerabilities" map`);
  }
  const advisories = new Map<string, ReportedAdvisory>();
  for (const entry of Object.values(vulnerabilities as Record<string, unknown>)) {
    const via = typeof entry === "object" && entry !== null ? (entry as { via?: unknown }).via : undefined;
    if (!Array.isArray(via)) continue;
    for (const cause of via) {
      if (typeof cause !== "object" || cause === null) continue;
      const { name, url, severity, title } = cause as Record<string, unknown>;
      if (typeof name !== "string" || typeof url !== "string") continue;
      advisories.set(`${name}\0${url}`, {
        tree,
        package: name,
        advisory: url,
        severity: typeof severity === "string" ? severity : "unknown",
        title: typeof title === "string" ? title : "",
      });
    }
  }
  return [...advisories.values()];
}

function advisorySection(root: string, trees: readonly AdvisoryTree[], accepted: readonly AcceptedAdvisory[]): Section {
  const findings: Finding[] = [];
  const reported: ReportedAdvisory[] = [];
  const judged = new Set<string>();
  for (const tree of trees) {
    try {
      if (typeof tree.directory === "string") {
        reported.push(...auditTree(tree.name, join(root, tree.directory), tree.args ?? []));
      } else {
        const prepared = tree.directory();
        try {
          reported.push(...auditTree(tree.name, prepared.directory, tree.args ?? []));
        } finally {
          prepared.dispose();
        }
      }
      judged.add(tree.name);
    } catch (error) {
      findings.push({
        outcome: error instanceof SourceUnavailable ? "unable" : "refused",
        text: `${tree.name} tree: ${errorText(error)}`,
      });
    }
  }

  const matches = (declaration: AcceptedAdvisory, advisory: ReportedAdvisory): boolean =>
    declaration.tree === advisory.tree &&
    declaration.package === advisory.package &&
    declaration.advisory === advisory.advisory;

  for (const advisory of reported) {
    const declaration = accepted.find((candidate) => matches(candidate, advisory));
    const subject = `${advisory.tree} tree: ${advisory.package} — ${advisory.severity}, ${advisory.title} (${advisory.advisory})`;
    findings.push(
      declaration === undefined
        ? {
            outcome: "refused",
            text: `${subject}. Fix it (an upgrade of the package that pulls it in, or an override) or declare it in ${CONFIG_FILE} with its reason.`,
          }
        : { outcome: "accepted", text: `${subject} — declared: ${declaration.reason}` },
    );
  }
  for (const declaration of accepted) {
    if (!trees.some((tree) => tree.name === declaration.tree)) {
      findings.push({
        outcome: "refused",
        text: `${CONFIG_FILE} declares ${declaration.advisory} in the ${declaration.tree} tree, and no audited tree has that name — remove the declaration.`,
      });
      continue;
    }
    if (!judged.has(declaration.tree)) continue;
    if (!reported.some((advisory) => matches(declaration, advisory))) {
      findings.push({
        outcome: "refused",
        text:
          `${CONFIG_FILE} declares ${declaration.advisory} in ${declaration.package} ` +
          `(${declaration.tree} tree), which npm audit no longer reports — remove the declaration.`,
      });
    }
  }
  return {
    title: "Advisories (npm audit)",
    findings,
    passed: `${String(judged.size)} of ${String(trees.length)} trees audited, ${String(reported.length)} advisories`,
  };
}

// ==========================================
// Report
// ==========================================

const MARK = { refused: "✗", unable: "?", accepted: "·" } as const;
const ORDER = ["refused", "unable", "accepted"] as const;

export function report(sections: readonly Section[]): { readonly text: string; readonly verdict: Verdict } {
  const lines: string[] = [];
  for (const section of sections) {
    lines.push(`${section.title}: ${section.passed}`);
    const ordered = [...section.findings].sort((left, right) => ORDER.indexOf(left.outcome) - ORDER.indexOf(right.outcome));
    for (const finding of ordered) lines.push(`  ${MARK[finding.outcome]} ${finding.text}`);
    lines.push("");
  }
  const all = sections.flatMap((section) => section.findings);
  const count = (outcome: Finding["outcome"]): number => all.filter((finding) => finding.outcome === outcome).length;
  const refused = count("refused");
  const unable = count("unable");
  const verdict: Verdict = refused > 0 ? "refused" : unable > 0 ? "unable" : "passed";
  lines.push(
    verdict === "passed"
      ? `Audit passed: nothing undeclared (${String(count("accepted"))} declared advisories).`
      : `Audit ${verdict === "refused" ? "refused" : "incomplete"}: ${String(refused)} undeclared, ` +
          `${String(unable)} not judged, ${String(count("accepted"))} declared. ` +
          "✗ — undeclared or dead; ? — could not be judged; · — declared.",
  );
  return { text: lines.join("\n"), verdict };
}

/** Exit codes of the command line: 0 passed, 1 refused, 2 not everything judged. */
export const EXIT_CODE: Readonly<Record<Verdict, number>> = { passed: 0, refused: 1, unable: 2 };

/** Audit one repository. */
export async function audit(options: AuditOptions): Promise<AuditResult> {
  let config: AuditConfig;
  try {
    config = options.config ?? readConfig(options.root);
  } catch (error) {
    const sections = [{ title: "Audit file", findings: [{ outcome: "refused" as const, text: errorText(error) }], passed: "not read" }];
    return { sections, ...report(sections) };
  }
  const trees = [...config.advisoryTrees, ...(options.advisoryTrees ?? [])];
  const sections: Section[] = [...(options.sections ?? [])];
  if (trees.length > 0 || config.acceptedAdvisories.length > 0) {
    sections.push(advisorySection(options.root, trees, config.acceptedAdvisories));
  }
  if (options.vulnerabilities !== undefined) {
    sections.push(vulnerabilitySection(options.vulnerabilities, config.acceptedVulnerabilities));
  }
  // An audit that judged nothing would pass by silence: a repository that
  // names no tree has not been audited, and the report says so.
  if (sections.length === 0) {
    sections.push({
      title: "Nothing to judge",
      findings: [
        {
          outcome: "refused",
          text: `no npm tree is named and no vulnerability scan was passed — list the trees consumers install in ${CONFIG_FILE} (advisoryTrees), or remove the audit from a repository that installs nothing from npm.`,
        },
      ],
      passed: "nothing audited",
    });
  }
  return { sections, ...report(sections) };
}
