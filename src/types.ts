// src/types.ts
/**
 * The vocabulary of the audit: what a repository uses, where the releases
 * of it are published, what the repository declares as kept on purpose,
 * and what the audit concludes.
 */

/** The releases a source publishes for one dependency. */
export interface ReleaseCatalog {
  /** Every published version, in the notation the use is compared in. */
  readonly versions: readonly string[];
  /**
   * The release the publisher designates as current, where the source has
   * such a designation (npm's `latest` tag). Absent, the newest version is
   * current.
   */
  readonly designated?: string;
}

/**
 * One place a repository fixes which release of a dependency it uses.
 *
 * `source` names where the releases are published — one of the built-in
 * sources (`npm`, `maven`, `gradle-plugin`, `gradle`, `crates`, `rust`,
 * `github-action`, `pin`) or one the caller defines (`AuditOptions.sources`).
 */
export interface DependencyUse {
  readonly source: string;
  readonly name: string;
  /** The release in use, in the notation of the source's catalog. */
  readonly version: string;
  /** Where the release is fixed — a file, or a file and what in it. */
  readonly site: string;
  /** The range the manifest declares, where the release is resolved from one (npm). */
  readonly declared?: string;
  /**
   * `line`: the use fixes a line, not a release — a GitHub Action referenced
   * by its major tag (`@v7`) follows every release of that major, so it is
   * current while the newest release lies on the line.
   */
  readonly precision?: "release" | "line";
}

/** Where one kind of dependency publishes its releases. */
export interface SourceDefinition {
  /** How the report names the source ("npm", "crate", "engine"). */
  readonly label: string;
  readonly catalog: (use: DependencyUse) => Promise<ReleaseCatalog>;
  /** How a newer release reaches the use — said in the report next to the lag. */
  readonly takeBy: (use: DependencyUse, newest: string) => string;
  /** The version as the source tags it, where that differs from the compared notation. */
  readonly tagOf?: (use: DependencyUse, version: string) => string;
}

/**
 * When the reason of an accepted lag is gone, where a machine can observe it.
 *
 * `requirer-admits` — the newest release of `package` (an npm package or a
 * crate, by the lag's source) accepts the newest release of the held
 * dependency: npm by its peer range, crates.io by its dependency
 * requirement. The tool that held the line supports the new one.
 *
 * `follows-use` — the dependency follows another use of the repository
 * (type declarations of the Node a package runs on): justified while that
 * use stays on the held line.
 */
export type LiftCondition =
  | { readonly kind: "requirer-admits"; readonly package: string }
  | { readonly kind: "follows-use"; readonly source: string; readonly name: string };

/** A dependency kept behind its newest release on purpose. */
export interface AcceptedLag {
  readonly source: string;
  readonly name: string;
  /** The line the use is held on — a prefix of the version by segments ("6", "0.8"). */
  readonly heldLine: string;
  /** The line the newest release lies on when the reason was written. */
  readonly coversLatestLine: string;
  readonly reason: string;
  /** The event that ends the reason, in words. */
  readonly reviewWhen: string;
  readonly liftedWhen?: LiftCondition | undefined;
}

/** A published advisory left in an audited tree on purpose. */
export interface AcceptedAdvisory {
  readonly tree: string;
  readonly package: string;
  /** The advisory address exactly as `npm audit` reports it. */
  readonly advisory: string;
  readonly reason: string;
  readonly reviewWhen: string;
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
