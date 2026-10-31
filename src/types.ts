// src/types.ts
/**
 * The vocabulary of the audit: the npm trees it judges, what the
 * repository declares as kept on purpose, and what the audit concludes.
 */

/** A published advisory left in an audited tree on purpose. */
export interface AcceptedAdvisory {
  readonly tree: string;
  readonly package: string;
  /** The advisory address exactly as `npm audit` reports it. */
  readonly advisory: string;
  readonly reason: string;
  /** The event that ends the reason, in words. */
  readonly reviewWhen: string;
}

/**
 * A vulnerability of a component left in a judged scope on purpose. A
 * scope is what the caller judges as one unit — the production
 * composition of an application, its development tooling, an engine, a
 * pinned tool — named by the caller, who also says which scopes a run
 * judged.
 */
export interface AcceptedVulnerability {
  readonly scope: string;
  /** The component as a package URL with its version, as the scanner reports it. */
  readonly purl: string;
  /** The bulletin: any identifier of it (GHSA, CVE, the ecosystem's own) — aliases of one bulletin are one bulletin. */
  readonly advisory: string;
  readonly reason: string;
  /** The event that ends the reason, in words. */
  readonly reviewWhen: string;
}

/** One bulletin against one component in one scope, as a vulnerability scan reported it. */
export interface ReportedVulnerability {
  readonly scope: string;
  readonly purl: string;
  /** The component's name as the scanner's ecosystem names it (group:artifact for Maven). */
  readonly name: string;
  readonly version: string;
  readonly ecosystem: string;
  /** The file the component was read from. */
  readonly source: string;
  /** The bulletin's leading identifier (a GHSA when it has one). */
  readonly advisory: string;
  /** Every identifier the bulletin and its aliases go by, the leading one included. */
  readonly identifiers: readonly string[];
  readonly summary: string;
  /** The highest severity score the scanner states for the bulletin, or "" when it states none. */
  readonly severity: string;
  /** The releases the bulletin names as fixed, every branch; empty when it names none. */
  readonly fixedVersions: readonly string[];
}

/** What a run judged for vulnerabilities: the reported ones and every scope the run covered, found or not. */
export interface JudgedVulnerabilities {
  readonly reported: readonly ReportedVulnerability[];
  readonly judgedScopes: readonly string[];
}

/** The structured judgement of a scan: what covers each finding, and which declarations cover nothing. */
export interface VulnerabilityJudgement {
  readonly findings: readonly {
    readonly reported: ReportedVulnerability;
    /** The declaration that keeps the finding on purpose, or null when it is undeclared. */
    readonly declaration: AcceptedVulnerability | null;
  }[];
  readonly dead: readonly {
    readonly declaration: AcceptedVulnerability;
    readonly cause: "scope-not-judged" | "no-longer-reported";
  }[];
}

/** An npm tree whose advisories are judged. */
export interface AdvisoryTree {
  readonly name: string;
  /**
   * The directory `npm audit` runs in, relative to the repository root — or,
   * for a tree the caller builds, a function that prepares the directory and
   * returns it with the way to remove it afterwards.
   */
  readonly directory: string | (() => { readonly directory: string; readonly dispose: () => void });
  /** Extra arguments of `npm audit` (`--omit=dev` for what consumers install without dev dependencies). */
  readonly args?: readonly string[];
}

/** Severity of one line of the report. */
export type Outcome = "refused" | "unable" | "accepted";

export interface Finding {
  readonly outcome: Outcome;
  readonly text: string;
}

export interface Section {
  readonly title: string;
  readonly findings: readonly Finding[];
  /** What was judged without remark, for the summary line. */
  readonly passed: string;
}

export type Verdict = "passed" | "refused" | "unable";
