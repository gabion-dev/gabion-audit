// src/audit.ts
/**
 * The audit of one repository: the freshness of every release it pins, and
 * the advisories in the npm trees it names.
 *
 * Only what is undeclared is red. A deviation kept on purpose is declared
 * in the audit file with its reason and the event that ends it; a
 * declaration that matches nothing any more is red as well, so an excuse
 * cannot outlive its cause and cover the next lag unjudged.
 *
 * Verdicts: passed — nothing undeclared; refused — an undeclared advisory
 * or lag, a dead declaration, an inventory that could not be read;
 * unable — something could not be judged (a source did not answer,
 * npm audit failed). A refusal outranks an inability.
 */

import { spawnSync } from "node:child_process";
import { join } from "node:path";
import semver from "semver";
import { builtinSources, cargoRange } from "./builtin-sources.js";
import { CONFIG_FILE, readConfig, type AuditConfig } from "./config.js";
import { cargoUses } from "./inventory/cargo.js";
import { githubActionUses } from "./inventory/github-actions.js";
import { gradleUses } from "./inventory/gradle.js";
import { npmUses } from "./inventory/npm.js";
import { pinUses } from "./inventory/pins.js";
import { rustToolchainUses } from "./inventory/rust-toolchain.js";
import { crateRequirements, currentRelease, npmPackument, SourceUnavailable } from "./sources.js";
import type {
  AcceptedAdvisory,
  AcceptedLag,
  AdvisoryTree,
  DependencyUse,
  Finding,
  ReleaseCatalog,
  Section,
  SourceDefinition,
  Verdict,
} from "./types.js";
import { compareVersions, isOnLine, isPreRelease, lineOf, newestOf } from "./versions.js";

export interface AuditOptions {
  /** The repository root: inventory, audit file and trees are read relative to it. */
  readonly root: string;
  /** The audit file, already read; read from `root` when absent. */
  readonly config?: AuditConfig;
  /** Uses the caller inventories itself — pins in its own code, a manifest of its own format. */
  readonly extraUses?: () => readonly DependencyUse[];
  /** Sources of the caller's own uses, by the `source` they carry. */
  readonly sources?: Readonly<Record<string, SourceDefinition>>;
  /** npm trees the caller prepares itself, judged with those of the audit file. */
  readonly advisoryTrees?: readonly AdvisoryTree[];
  /** Sections the caller judged itself (a policy of its own), reported first. */
  readonly sections?: readonly Section[];
}

export interface AuditResult {
  readonly sections: readonly Section[];
  readonly verdict: Verdict;
  readonly text: string;
}

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
// Freshness
// ==========================================

interface UseJudgement {
  readonly use: DependencyUse;
  /** The release the source calls current; undefined when the source could not be read. */
  readonly newest?: string;
  readonly finding?: Finding;
  /** The declaration that accepted this use's lag. */
  readonly acceptedBy?: AcceptedLag;
}

/** isOnLine for registry versions, which may be in notations the ordering rule cannot read. */
function isOnLineSafe(version: string, line: string): boolean {
  try {
    return isOnLine(version, line);
  } catch {
    // A version the ordering rule cannot read cannot lie on a line either:
    // the registry lists what publishers uploaded, and newestOf skips the
    // same versions for the same reason.
    return false;
  }
}

class Judge {
  private readonly catalogs = new Map<string, Promise<ReleaseCatalog>>();

  constructor(
    private readonly sources: Readonly<Record<string, SourceDefinition>>,
    private readonly lags: readonly AcceptedLag[],
  ) {}

  sourceOf(use: DependencyUse): SourceDefinition {
    const source = this.sources[use.source];
    if (source === undefined) throw new Error(`no source defined for "${use.source}" uses`);
    return source;
  }

  private catalogFor(use: DependencyUse): Promise<ReleaseCatalog> {
    const key = `${use.source}\0${use.name}`;
    const cached = this.catalogs.get(key);
    if (cached !== undefined) return cached;
    const loading = this.sourceOf(use).catalog(use);
    this.catalogs.set(key, loading);
    return loading;
  }

  private shown(use: DependencyUse, version: string): string {
    const tagOf = this.sourceOf(use).tagOf;
    return tagOf === undefined ? version : tagOf(use, version);
  }

  label(source: string): string {
    return this.sources[source]?.label ?? source;
  }

  async judge(use: DependencyUse): Promise<UseJudgement> {
    let subject = `${use.source} ${use.name} ${use.version} (${use.site})`;
    let source: SourceDefinition;
    let catalog: ReleaseCatalog;
    try {
      source = this.sourceOf(use);
      subject = `${source.label} ${use.name} ${this.shown(use, use.version)} (${use.site})`;
      catalog = await this.catalogFor(use);
    } catch (error) {
      return {
        use,
        finding: { outcome: error instanceof SourceUnavailable ? "unable" : "refused", text: `${subject}: ${errorText(error)}` },
      };
    }
    const usedIsPreRelease = isPreRelease(use.version);
    const newest = currentRelease(catalog, usedIsPreRelease);
    if (newest === undefined) {
      return { use, finding: { outcome: "unable", text: `${subject}: the source lists no release to compare with` } };
    }
    const current =
      use.precision === "line" ? isOnLineSafe(newest, use.version) : compareVersions(use.version, newest) >= 0;
    if (current) return { use, newest };

    const behind = `${subject} — newest ${this.shown(use, newest)}`;
    const declaration = this.lags.find((candidate) => candidate.source === use.source && candidate.name === use.name);
    if (declaration === undefined) {
      return {
        use,
        newest,
        finding: {
          outcome: "refused",
          text: `${behind}. Take it (${source.takeBy(use, newest)}) or declare the lag in ${CONFIG_FILE} with its reason.`,
        },
      };
    }
    if (!isOnLine(use.version, declaration.heldLine) || !isOnLine(newest, declaration.coversLatestLine)) {
      return {
        use,
        newest,
        finding: {
          outcome: "refused",
          text:
            `${behind}. ${CONFIG_FILE} accepts ${use.name} held on ${declaration.heldLine} ` +
            `while the newest release is on ${declaration.coversLatestLine}; here the use is on ` +
            `${lineOf(use.version, declaration.heldLine)} and the newest on ` +
            `${lineOf(newest, declaration.coversLatestLine)} — a case the declared reason was not written for: judge it again.`,
        },
      };
    }
    if (use.precision !== "line") {
      const newestOnHeldLine = newestOf(
        catalog.versions.filter((version) => isOnLineSafe(version, declaration.heldLine)),
        usedIsPreRelease,
      );
      if (newestOnHeldLine !== undefined && compareVersions(use.version, newestOnHeldLine) < 0) {
        return {
          use,
          newest,
          finding: {
            outcome: "refused",
            text:
              `${subject} — held on ${declaration.heldLine} as declared, but ${this.shown(use, newestOnHeldLine)} is the ` +
              `newest release of that line. Take it (${source.takeBy(use, newestOnHeldLine)}).`,
          },
        };
      }
    }
    return {
      use,
      newest,
      acceptedBy: declaration,
      finding: { outcome: "accepted", text: `${behind} — declared: ${declaration.reason}` },
    };
  }

  /** Why an accepted lag no longer protects anything; undefined while it still does. */
  async dead(declaration: AcceptedLag, judgements: readonly UseJudgement[]): Promise<string | undefined> {
    const label = `${CONFIG_FILE}: ${this.label(declaration.source)} ${declaration.name} held on ${declaration.heldLine}`;
    const uses = judgements.filter(
      (judgement) => judgement.use.source === declaration.source && judgement.use.name === declaration.name,
    );
    if (uses.length === 0) return `${label} — the repository uses no such dependency: remove the declaration.`;
    // Undecidable while a source did not answer; the unanswered use is
    // already reported as such.
    if (uses.some((judgement) => judgement.newest === undefined)) return undefined;
    if (!uses.some((judgement) => judgement.acceptedBy === declaration)) {
      return `${label} — no use of it lags under this declaration any more: remove the declaration.`;
    }

    const lift = declaration.liftedWhen;
    if (lift === undefined) return undefined;
    const newest = uses.find((judgement) => judgement.newest !== undefined)?.newest;
    switch (lift.kind) {
      case "requirer-admits": {
        const admitted = await this.requirerRange(declaration, lift.package);
        if (admitted.range === undefined) {
          return `${label} — ${lift.package} ${admitted.release} declares no requirement on ${declaration.name}, so the declared reason can no longer be observed: judge the lag again.`;
        }
        if (newest !== undefined && semver.satisfies(newest, admitted.range)) {
          return `${label} — ${lift.package} ${admitted.release} admits ${declaration.name} ${newest} (${admitted.range}): the reason is gone, take the newer line and remove the declaration.`;
        }
        return undefined;
      }
      case "follows-use": {
        const followed = judgements.filter(
          (judgement) => judgement.use.source === lift.source && judgement.use.name === lift.name,
        );
        if (followed.length === 0) {
          return `${label} — it follows ${lift.source} ${lift.name}, which the repository does not use: judge the lag again.`;
        }
        const off = followed.find((judgement) => !isOnLineSafe(judgement.use.version, declaration.heldLine));
        if (off !== undefined) {
          return `${label} — ${lift.name} is at ${off.use.version} (${off.use.site}), off the held line: move ${declaration.name} with it and remove the declaration.`;
        }
        return undefined;
      }
    }
  }

  /** The range the newest release of `requirer` declares for the held dependency, as a semver range. */
  private async requirerRange(
    declaration: AcceptedLag,
    requirer: string,
  ): Promise<{ readonly release: string; readonly range?: string }> {
    if (declaration.source === "npm") {
      const packument = await npmPackument(requirer);
      const release = currentRelease(packument.catalog, false);
      if (release === undefined) throw new SourceUnavailable(`${requirer} lists no release`);
      const range = packument.peerRanges.get(release)?.[declaration.name];
      return range === undefined ? { release } : { release, range };
    }
    if (declaration.source === "crates") {
      const release = currentRelease(await this.catalogFor({ source: "crates", name: requirer, version: "0", site: "" }), false);
      if (release === undefined) throw new SourceUnavailable(`${requirer} lists no release`);
      const requirement = (await crateRequirements(requirer, release))[declaration.name];
      const range = requirement === undefined ? null : cargoRange(requirement);
      return range === null ? { release } : { release, range };
    }
    throw new Error(`requirer-admits is observable for npm and crates lags, not ${declaration.source}`);
  }
}

function inventory(root: string, config: AuditConfig, extra?: () => readonly DependencyUse[]): DependencyUse[] {
  const names = config.pins.map((pin) => pin.name);
  const repeated = names.find((name, index) => names.indexOf(name) !== index);
  if (repeated !== undefined) {
    throw new Error(`${CONFIG_FILE}: two pins are named ${repeated} — a pin's name is its identity`);
  }
  return [
    ...npmUses(root),
    ...cargoUses(root),
    ...rustToolchainUses(root),
    ...gradleUses(root),
    ...githubActionUses(root),
    ...pinUses(root, config.pins),
    ...(extra?.() ?? []),
  ];
}

async function freshnessSection(root: string, config: AuditConfig, options: AuditOptions): Promise<Section> {
  const judge = new Judge({ ...builtinSources(config.pins), ...options.sources }, config.acceptedLags);
  let uses: readonly DependencyUse[];
  try {
    uses = inventory(root, config, options.extraUses);
  } catch (error) {
    return { title: "Freshness", findings: [{ outcome: "refused", text: `inventory: ${errorText(error)}` }], passed: "nothing judged" };
  }
  const judgements = await Promise.all(uses.map((use) => judge.judge(use)));
  const findings = judgements
    .map((judgement) => judgement.finding)
    .filter((finding): finding is Finding => finding !== undefined);
  for (const declaration of config.acceptedLags) {
    try {
      const dead = await judge.dead(declaration, judgements);
      if (dead !== undefined) findings.push({ outcome: "refused", text: dead });
    } catch (error) {
      findings.push({
        outcome: error instanceof SourceUnavailable ? "unable" : "refused",
        text: `${CONFIG_FILE}: ${declaration.name}: ${errorText(error)}`,
      });
    }
  }
  const current = judgements.filter((judgement) => judgement.finding === undefined).length;
  return { title: "Freshness", findings, passed: `${String(current)} of ${String(judgements.length)} uses at the newest release` };
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
      ? `Audit passed: nothing undeclared (${String(count("accepted"))} declared deviations).`
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
  const sections = [
    ...(options.sections ?? []),
    ...(trees.length > 0 || config.acceptedAdvisories.length > 0
      ? [advisorySection(options.root, trees, config.acceptedAdvisories)]
      : []),
    await freshnessSection(options.root, config, options),
  ];
  return { sections, ...report(sections) };
}
