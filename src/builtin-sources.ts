// src/builtin-sources.ts
/**
 * The sources the audit knows by itself: one per kind of use its inventory
 * finds, and the source of every pin the audit file declares.
 */

import semver from "semver";
import type { Pin, PinSource } from "./config.js";
import {
  cratesCatalog,
  fetchJson,
  githubReleaseCatalog,
  githubTagCatalog,
  gradleCatalog,
  gradlePluginCatalog,
  isRecord,
  listingCatalog,
  mavenCatalog,
  npmPackument,
  rustCatalog,
  unexpectedShape,
} from "./sources.js";
import type { DependencyUse, ReleaseCatalog, SourceDefinition } from "./types.js";

const atTheSite = (): string => "change the version at the site";

function pinCatalog(source: PinSource): Promise<ReleaseCatalog> {
  switch (source.kind) {
    case "github-releases":
      return githubReleaseCatalog(source.repository, new RegExp(source.tagPattern));
    case "github-tags":
      return githubTagCatalog(source.repository, new RegExp(source.tagPattern));
    case "npm":
      return npmPackument(source.package).then((packument) => packument.catalog);
    case "crates":
      return cratesCatalog(source.crate);
    case "maven":
      return mavenCatalog(source.coordinate);
    case "listing":
      return listingCatalog(source.url, new RegExp(source.pattern));
  }
}

/** Java long-term-support feature releases: a toolchain moves from one LTS to the next. */
async function javaLtsCatalog(): Promise<ReleaseCatalog> {
  const url = "https://api.adoptium.net/v3/info/available_releases";
  const info = await fetchJson(url);
  const lts = isRecord(info) ? info["available_lts_releases"] : undefined;
  if (!Array.isArray(lts)) throw unexpectedShape(url, "available_lts_releases");
  return { versions: lts.filter((feature) => typeof feature === "number").map(String) };
}

export function builtinSources(pins: readonly Pin[]): Readonly<Record<string, SourceDefinition>> {
  const pinNamed = (use: DependencyUse): Pin => {
    const pin = pins.find((candidate) => candidate.name === use.name);
    if (pin === undefined) throw new Error(`no pin named ${use.name} in the audit file`);
    return pin;
  };
  return {
    npm: {
      label: "npm",
      catalog: (use) => npmPackument(use.name).then((packument) => packument.catalog),
      takeBy: (use, newest) =>
        use.declared !== undefined && semver.validRange(use.declared) !== null && !semver.satisfies(newest, use.declared)
          ? `the range ${use.declared} excludes it: raise the range`
          : "inside the declared range: npm update takes it",
    },
    crates: {
      label: "crate",
      catalog: (use) => cratesCatalog(use.name),
      takeBy: (use, newest) => {
        const range = use.declared === undefined ? null : cargoRange(use.declared);
        return range !== null && !semver.satisfies(newest, range)
          ? `the requirement ${String(use.declared)} excludes it: raise it in the manifest`
          : "inside the requirement: cargo update takes it";
      },
    },
    maven: { label: "Maven", catalog: (use) => mavenCatalog(use.name), takeBy: atTheSite },
    "gradle-plugin": { label: "Gradle plugin", catalog: (use) => gradlePluginCatalog(use.name), takeBy: atTheSite },
    gradle: {
      label: "Gradle",
      catalog: () => gradleCatalog(),
      takeBy: () => "move distributionUrl and distributionSha256Sum of its wrapper to that release",
    },
    java: {
      label: "Java LTS",
      catalog: () => javaLtsCatalog(),
      takeBy: () => "the Java toolchain of the build, with every JDK the repository runs it on",
    },
    rust: {
      label: "Rust",
      catalog: () => rustCatalog(),
      takeBy: () => "the channel in rust-toolchain.toml",
    },
    "github-action": {
      label: "GitHub Action",
      catalog: (use) => githubReleaseCatalog(use.name, /^v?(\d+(?:\.\d+)*)$/),
      takeBy: (use, newest) =>
        use.precision === "line" ? `the reference @v${newest.split(".")[0] ?? newest}` : `the reference @v${newest}`,
    },
    pin: {
      label: "pinned",
      catalog: (use) => pinCatalog(pinNamed(use).source),
      takeBy: (use) => pinNamed(use).takeBy,
    },
  };
}

/**
 * A Cargo version requirement as a semver range: a bare version is a caret
 * requirement in Cargo ("0.8.22" admits 0.8.x from .22), and comparators
 * are separated by commas instead of spaces. Null when it cannot be read.
 */
export function cargoRange(requirement: string): string | null {
  const range = requirement
    .split(",")
    .map((part) => part.trim())
    .map((part) => (/^\d/.test(part) ? `^${part}` : part.replace(/^=\s*/, "")))
    .join(" ");
  return semver.validRange(range);
}
