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
