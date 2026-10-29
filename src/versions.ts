// src/versions.ts
/**
 * Ordering of release versions across every source the audit reads: npm,
 * crates.io and Maven versions, Gradle and Rust releases, tags reduced to
 * the upstream version they name.
 *
 * One rule covers them all: a numeric core of dot-separated segments,
 * optionally followed by a qualifier ("-rc.1", "-M2", "-dev.7", ".Final").
 * Missing segments count as zero, so "25" equals "25.0.0". A qualifier
 * marks a pre-release unless it is one of the few that Maven artifacts
 * use for ordinary releases. Pre-releases order below the release of the
 * same core and among themselves segment by segment, numbers numerically.
 *
 * A version this rule cannot read is an error, not a guess: ordering it
 * by some fallback would report a fresh dependency as stale or, worse, a
 * stale one as fresh.
 */

interface ParsedVersion {
  readonly core: readonly number[];
  /** Qualifier segments of a pre-release; empty for a release. */
  readonly preRelease: readonly string[];
}

const VERSION_PATTERN = /^v?(\d+(?:\.\d+)*)(?:[-.+]?([0-9A-Za-z][0-9A-Za-z.-]*))?$/;

/** Qualifiers Maven artifacts publish ordinary releases under. */
const RELEASE_QUALIFIERS: ReadonlySet<string> = new Set(["final", "ga", "release", "jre"]);

function parse(version: string): ParsedVersion {
  const match = VERSION_PATTERN.exec(version);
  const core = match?.[1];
  if (match === null || core === undefined) {
    throw new Error(`"${version}" is not a release version this audit can order`);
  }
  const qualifier = match[2];
  const preRelease =
    qualifier === undefined || RELEASE_QUALIFIERS.has(qualifier.toLowerCase())
      ? []
      : qualifier.split(/[.-]/);
  return { core: core.split(".").map(Number), preRelease };
}

function compareSegments(left: string, right: string): number {
  const leftNumber = /^\d+$/.test(left) ? Number(left) : undefined;
  const rightNumber = /^\d+$/.test(right) ? Number(right) : undefined;
  if (leftNumber !== undefined && rightNumber !== undefined) {
    return leftNumber - rightNumber;
  }
  // A numeric segment orders below a textual one, as in semver.
  if (leftNumber !== undefined) return -1;
  if (rightNumber !== undefined) return 1;
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Negative when `left` is older, positive when newer, zero when equal. */
export function compareVersions(left: string, right: string): number {
  const a = parse(left);
  const b = parse(right);
  const length = Math.max(a.core.length, b.core.length);
  for (let index = 0; index < length; index++) {
    const difference = (a.core[index] ?? 0) - (b.core[index] ?? 0);
    if (difference !== 0) return difference;
  }
  if (a.preRelease.length === 0 || b.preRelease.length === 0) {
    return b.preRelease.length - a.preRelease.length;
  }
  const qualifierLength = Math.max(a.preRelease.length, b.preRelease.length);
  for (let index = 0; index < qualifierLength; index++) {
    const left = a.preRelease[index];
    const right = b.preRelease[index];
    if (left === undefined) return -1;
    if (right === undefined) return 1;
    const difference = compareSegments(left, right);
    if (difference !== 0) return difference;
  }
  return 0;
}

export function isPreRelease(version: string): boolean {
  return parse(version).preRelease.length > 0;
}

/** Whether `version` lies on `line` — a prefix of its numeric core ("6", "0.99"). */
export function isOnLine(version: string, line: string): boolean {
  const { core } = parse(version);
  const prefix = parse(line).core;
  return prefix.every((segment, index) => (core[index] ?? 0) === segment);
}

/** The line of `version` at the depth of `line`: "24.19.2" at the depth of "26" is "24". */
export function lineOf(version: string, line: string): string {
  return parse(version).core.slice(0, parse(line).core.length).join(".");
}

/**
 * The newest of `versions` — releases only, unless `withPreReleases`: a
 * dependency used at a pre-release is compared with pre-releases, the way
 * npm resolves a pre-release range. Undefined when nothing qualifies.
 * Versions this rule cannot read are skipped here: a registry lists
 * whatever its publishers uploaded, and only the readable ones can be
 * ordered — the used version itself is always parsed strictly.
 */
export function newestOf(
  versions: Iterable<string>,
  withPreReleases: boolean,
): string | undefined {
  let newest: string | undefined;
  for (const version of versions) {
    if (!VERSION_PATTERN.test(version)) continue;
    if (!withPreReleases && isPreRelease(version)) continue;
    if (newest === undefined || compareVersions(version, newest) > 0) {
      newest = version;
    }
  }
  return newest;
}
