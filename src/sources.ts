// src/sources.ts
/**
 * Where the audit learns which releases exist: the npm registry, crates.io,
 * Maven Central, the Gradle plugin portal, the Gradle and Rust release
 * lists, GitHub releases and tags, and listing pages a pin names.
 *
 * A source that does not answer makes its dependencies unjudgeable, never
 * current: the error travels to the report as the reason those
 * dependencies could not be judged.
 */

import type { ReleaseCatalog } from "./types.js";
import { newestOf } from "./versions.js";

/**
 * How long one request may go unanswered. A response is the one event a
 * request waits for and it may never come (a stalled connection on a
 * network that drops packets); past this the source is reported as
 * unavailable instead of holding the audit forever.
 */
const RESPONSE_TIMEOUT_MS = 30_000;

/** crates.io refuses requests without a user agent that names the client. */
const USER_AGENT = "gabion-audit (https://github.com/gabion-dev/gabion-audit)";

/** A source that could not be read; the report names it as the reason a judgement is missing. */
export class SourceUnavailable extends Error {}

async function fetchFrom(url: string, accept: string): Promise<Response> {
  const headers: Record<string, string> = { Accept: accept, "User-Agent": USER_AGENT };
  // The GitHub API answers sixty unauthenticated requests an hour per
  // address; a token, where the environment has one, lifts that limit.
  const token = process.env["GITHUB_TOKEN"];
  if (url.startsWith("https://api.github.com/") && token !== undefined && token !== "") {
    headers["Authorization"] = `Bearer ${token}`;
  }
  let response: Response;
  try {
    response = await fetch(url, { headers, signal: AbortSignal.timeout(RESPONSE_TIMEOUT_MS) });
  } catch (error) {
    throw new SourceUnavailable(`${url}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!response.ok) {
    const limited =
      url.startsWith("https://api.github.com/") && (response.status === 403 || response.status === 429)
        ? " — the GitHub API rate limit; set GITHUB_TOKEN to lift it"
        : "";
    throw new SourceUnavailable(`${url}: HTTP ${String(response.status)}${limited}`);
  }
  return response;
}

export async function fetchJson(url: string, accept = "application/json"): Promise<unknown> {
  const response = await fetchFrom(url, accept);
  try {
    return await response.json();
  } catch (error) {
    throw new SourceUnavailable(
      `${url}: the answer is not JSON (${error instanceof Error ? error.message : String(error)})`,
    );
  }
}

export async function fetchText(url: string): Promise<string> {
  return (await fetchFrom(url, "text/html, application/xml, text/plain")).text();
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function unexpectedShape(url: string, what: string): SourceUnavailable {
  return new SourceUnavailable(`${url}: the answer carries no ${what}`);
}

/**
 * One request per key for the whole audit: the same package is used by
 * several workspaces, the same action by several workflows.
 */
function memoized<T>(load: (key: string) => Promise<T>): (key: string) => Promise<T> {
  const loaded = new Map<string, Promise<T>>();
  return (key) => {
    const cached = loaded.get(key);
    if (cached !== undefined) return cached;
    const loading = load(key);
    loaded.set(key, loading);
    return loading;
  };
}

/** One request for the whole audit, for a source that answers one list. */
function once<T>(load: () => Promise<T>): () => Promise<T> {
  let loading: Promise<T> | undefined;
  return () => (loading ??= load());
}

/**
 * The release a catalog calls current: the publisher's designation where
 * there is one, else the newest release — pre-releases included only for
 * a use that is itself at a pre-release.
 */
export function currentRelease(catalog: ReleaseCatalog, usedIsPreRelease: boolean): string | undefined {
  return catalog.designated ?? newestOf(catalog.versions, usedIsPreRelease);
}

// ==========================================
// npm
// ==========================================

/** One npm package's abbreviated registry document. */
export interface NpmPackument {
  readonly catalog: ReleaseCatalog;
  /** Peer ranges each version declares, by peer name. */
  readonly peerRanges: ReadonlyMap<string, Readonly<Record<string, string>>>;
}

/**
 * The package's releases and the peer ranges they declare, from the
 * abbreviated document — the one npm itself installs from.
 */
export const npmPackument = memoized(async (name: string): Promise<NpmPackument> => {
  const url = `https://registry.npmjs.org/${name.replace("/", "%2f")}`;
  const document = await fetchJson(url, "application/vnd.npm.install-v1+json");
  if (!isRecord(document) || !isRecord(document["versions"])) {
    throw unexpectedShape(url, "versions");
  }
  const tags = document["dist-tags"];
  const latest = isRecord(tags) ? tags["latest"] : undefined;
  const peerRanges = new Map<string, Readonly<Record<string, string>>>();
  for (const [version, manifest] of Object.entries(document["versions"])) {
    const peers = isRecord(manifest) ? manifest["peerDependencies"] : undefined;
    if (isRecord(peers)) {
      const ranges: Record<string, string> = {};
      for (const [peer, range] of Object.entries(peers)) {
        if (typeof range === "string") ranges[peer] = range;
      }
      peerRanges.set(version, ranges);
    }
  }
  return {
    catalog: {
      versions: Object.keys(document["versions"]),
      ...(typeof latest === "string" ? { designated: latest } : {}),
    },
    peerRanges,
  };
});

// ==========================================
// crates.io
// ==========================================

/** Releases of a crate, yanked ones left out. */
export const cratesCatalog = memoized(async (name: string): Promise<ReleaseCatalog> => {
  const url = `https://crates.io/api/v1/crates/${encodeURIComponent(name)}`;
  const document = await fetchJson(url);
  const versions = isRecord(document) ? document["versions"] : undefined;
  if (!Array.isArray(versions)) throw unexpectedShape(url, "versions");
  const released: string[] = [];
  for (const version of versions) {
    if (!isRecord(version) || version["yanked"] === true) continue;
    if (typeof version["num"] === "string") released.push(version["num"]);
  }
  return { versions: released };
});

/**
 * The requirement each normal dependency of one crate release declares, by
 * dependency name — as Cargo writes it ("0.8.22", "^1", ">=1, <3").
 */
export async function crateRequirements(name: string, version: string): Promise<Readonly<Record<string, string>>> {
  const url = `https://crates.io/api/v1/crates/${encodeURIComponent(name)}/${encodeURIComponent(version)}/dependencies`;
  const document = await fetchJson(url);
  const dependencies = isRecord(document) ? document["dependencies"] : undefined;
  if (!Array.isArray(dependencies)) throw unexpectedShape(url, "dependencies");
  const requirements: Record<string, string> = {};
  for (const dependency of dependencies) {
    if (!isRecord(dependency) || dependency["kind"] !== "normal") continue;
    const { crate_id: crate, req } = dependency;
    if (typeof crate === "string" && typeof req === "string") requirements[crate] = req;
  }
  return requirements;
}

// ==========================================
// Maven Central, the Gradle plugin portal, Gradle
// ==========================================

async function mavenMetadataVersions(url: string): Promise<readonly string[]> {
  const metadata = await fetchText(url);
  const versions = [...metadata.matchAll(/<version>([^<]+)<\/version>/g)]
    .map((match) => match[1])
    .filter((version): version is string => version !== undefined);
  if (versions.length === 0) throw unexpectedShape(url, "<version> entries");
  return versions;
}

/** Releases of a Maven artifact, `group:artifact`. */
export const mavenCatalog = memoized(async (coordinate: string): Promise<ReleaseCatalog> => {
  const [group, artifact] = coordinate.split(":");
  if (group === undefined || artifact === undefined) {
    throw new Error(`"${coordinate}" is not a group:artifact pair`);
  }
  const url = `https://repo1.maven.org/maven2/${group.replaceAll(".", "/")}/${artifact}/maven-metadata.xml`;
  return { versions: await mavenMetadataVersions(url) };
});

/** Releases of a Gradle plugin, by plugin id (its marker artifact on the plugin portal). */
export const gradlePluginCatalog = memoized(async (pluginId: string): Promise<ReleaseCatalog> => {
  const url =
    `https://plugins.gradle.org/m2/${pluginId.replaceAll(".", "/")}/` +
    `${pluginId}.gradle.plugin/maven-metadata.xml`;
  return { versions: await mavenMetadataVersions(url) };
});

/** Releases of Gradle itself — snapshots, nightlies and broken releases left out. */
export const gradleCatalog = once(async (): Promise<ReleaseCatalog> => {
  const url = "https://services.gradle.org/versions/all";
  const releases = await fetchJson(url);
  if (!Array.isArray(releases)) throw unexpectedShape(url, "release list");
  const versions: string[] = [];
  for (const release of releases) {
    if (!isRecord(release) || typeof release["version"] !== "string") continue;
    if (release["snapshot"] === true || release["nightly"] === true || release["broken"] === true) continue;
    versions.push(release["version"]);
  }
  return { versions };
});

// ==========================================
// Rust
// ==========================================

/**
 * The current stable Rust release, from the stable channel manifest rustup
 * installs from. Only the current release is listed there, and that is the
 * one a pinned toolchain is compared with.
 */
export const rustCatalog = once(async (): Promise<ReleaseCatalog> => {
  const url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
  const manifest = await fetchText(url);
  const version = /^\[pkg\.rust\]\s*\nversion\s*=\s*"(\d+\.\d+\.\d+)[^"]*"/m.exec(manifest)?.[1];
  if (version === undefined) throw unexpectedShape(url, "[pkg.rust] version");
  return { versions: [version] };
});

// ==========================================
// GitHub
// ==========================================

/** Each tag through `pattern`: the first capture group is the version; a tag that does not match is not a release of it. */
function versionsOfTags(tags: readonly string[], pattern: RegExp): string[] {
  const versions: string[] = [];
  for (const tag of tags) {
    const version = pattern.exec(tag)?.[1];
    if (version !== undefined) versions.push(version);
  }
  return versions;
}

/** Tags of a repository's GitHub releases, drafts left out. */
export const githubReleaseTags = memoized(async (repository: string): Promise<readonly string[]> => {
  const url = `https://api.github.com/repos/${repository}/releases?per_page=100`;
  const releases = await fetchJson(url);
  if (!Array.isArray(releases)) throw unexpectedShape(url, "release list");
  const tags: string[] = [];
  for (const release of releases) {
    if (!isRecord(release) || release["draft"] === true) continue;
    if (typeof release["tag_name"] === "string") tags.push(release["tag_name"]);
  }
  return tags;
});

/** A repository's git tags — for upstreams that tag releases without publishing GitHub releases. */
export const githubTags = memoized(async (repository: string): Promise<readonly string[]> => {
  const url = `https://api.github.com/repos/${repository}/tags?per_page=100`;
  const tags = await fetchJson(url);
  if (!Array.isArray(tags)) throw unexpectedShape(url, "tag list");
  return tags.flatMap((tag) => (isRecord(tag) && typeof tag["name"] === "string" ? [tag["name"]] : []));
});

export async function githubReleaseCatalog(repository: string, tagPattern: RegExp): Promise<ReleaseCatalog> {
  return { versions: versionsOfTags(await githubReleaseTags(repository), tagPattern) };
}

export async function githubTagCatalog(repository: string, tagPattern: RegExp): Promise<ReleaseCatalog> {
  return { versions: versionsOfTags(await githubTags(repository), tagPattern) };
}

/** Versions a listing page names, each the first capture group of `pattern`. */
export async function listingCatalog(url: string, pattern: RegExp): Promise<ReleaseCatalog> {
  const page = await fetchText(url);
  const global = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  const versions = [...page.matchAll(global)]
    .map((match) => match[1])
    .filter((version): version is string => version !== undefined);
  if (versions.length === 0) throw unexpectedShape(url, `a match of ${pattern.source}`);
  return { versions };
}
