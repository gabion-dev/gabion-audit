// src/inventory/gradle.ts
/**
 * Gradle: plugins and library coordinates of every tracked Kotlin-script
 * build, the Java toolchain it compiles for, the release each wrapper runs.
 *
 * A version written in a form the patterns below do not read, or one that
 * is not a literal, is an error naming the site — a dependency silently
 * missed would be reported as nothing, which reads exactly like a current
 * one.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { DependencyUse } from "../types.js";
import { lineAt, trackedFiles } from "./git.js";

/**
 * The text with comments blanked out and line breaks kept, so a version
 * quoted in a comment is not taken for a declaration and an error can
 * still name the line. Strings are tracked so "//" inside an address is
 * not taken for a comment.
 */
function withoutKotlinComments(text: string): string {
  let result = "";
  let index = 0;
  let inString = false;
  while (index < text.length) {
    const char = text[index] ?? "";
    const next = text[index + 1] ?? "";
    if (inString) {
      result += char;
      if (char === "\\") {
        result += next;
        index += 2;
        continue;
      }
      if (char === '"') inString = false;
      index++;
      continue;
    }
    if (char === '"') {
      inString = true;
      result += char;
      index++;
      continue;
    }
    if (char === "/" && next === "/") {
      while (index < text.length && text[index] !== "\n") {
        result += " ";
        index++;
      }
      continue;
    }
    if (char === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      const stop = end === -1 ? text.length : end + 2;
      result += text.slice(index, stop).replace(/[^\n]/g, " ");
      index = stop;
      continue;
    }
    result += char;
    index++;
  }
  return result;
}

const PLUGIN_DECLARATION = /id\("([^"]+)"\)\s*version\s*"([^"]+)"/g;
/**
 * A "group:artifact:version" literal. A Maven version holds neither ":" nor
 * "/", which keeps an address such as "scm:git:https://…" from reading as a
 * coordinate.
 */
const COORDINATE_LITERAL = /"([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"\s:/]+)"/g;
const LITERAL_VERSION = /^\d[^:@$]*$/;
const TOOLCHAIN_DECLARATION = /JavaLanguageVersion\.of\((\d+)\)/g;
/** Version forms the patterns above do not read; meeting one is an error, not a skip. */
const UNREAD_VERSION_FORMS = /\bversion\s*\(|\bversion\s+"|\bstrictly\s*\(|\brequire\s*\(\s*"|\bprefer\s*\(/g;

function gradleBuildUses(path: string, source: string): DependencyUse[] {
  const text = withoutKotlinComments(source);
  const uses: DependencyUse[] = [];
  const readOffsets = new Set<number>();

  for (const match of text.matchAll(PLUGIN_DECLARATION)) {
    const [, id, version] = match;
    if (id === undefined || version === undefined) continue;
    readOffsets.add(match.index + match[0].indexOf("version"));
    uses.push({ source: "gradle-plugin", name: id, version, site: path });
  }

  for (const match of text.matchAll(COORDINATE_LITERAL)) {
    const [, group, artifact, version] = match;
    if (group === undefined || artifact === undefined || version === undefined) continue;
    if (!LITERAL_VERSION.test(version)) {
      throw new Error(
        `${path}:${String(lineAt(text, match.index))}: "${group}:${artifact}:${version}" — ` +
          "the version is not a literal release, so the dependency audit cannot tell which release is used",
      );
    }
    uses.push({ source: "maven", name: `${group}:${artifact}`, version, site: path });
  }

  for (const match of text.matchAll(TOOLCHAIN_DECLARATION)) {
    const [, feature] = match;
    if (feature === undefined) continue;
    uses.push({ source: "java", name: "java", version: feature, site: `${path} (Java toolchain)` });
  }

  for (const match of text.matchAll(UNREAD_VERSION_FORMS)) {
    if (readOffsets.has(match.index)) continue;
    throw new Error(
      `${path}:${String(lineAt(text, match.index))}: a version declared as "${match[0].trim()}…" — ` +
        "a form the dependency audit does not read; declare it as id(\"…\") version \"…\" or as a " +
        "\"group:artifact:version\" literal",
    );
  }
  return uses;
}

const WRAPPER_DISTRIBUTION = /^distributionUrl=.*\/gradle-([^/]+)-(?:bin|all)\.zip\s*$/m;

function gradleWrapperUse(path: string, source: string): DependencyUse {
  const version = WRAPPER_DISTRIBUTION.exec(source)?.[1];
  if (version === undefined) {
    throw new Error(`${path}: no distributionUrl naming a Gradle release`);
  }
  return { source: "gradle", name: "gradle", version, site: dirname(dirname(dirname(path))) };
}

export function gradleUses(repoRoot: string): DependencyUse[] {
  const uses: DependencyUse[] = [];
  for (const path of trackedFiles(repoRoot, [":(glob)**/*.gradle.kts"])) {
    uses.push(...gradleBuildUses(path, readFileSync(join(repoRoot, path), "utf-8")));
  }
  for (const path of trackedFiles(repoRoot, [":(glob)**/gradle/wrapper/gradle-wrapper.properties"])) {
    uses.push(gradleWrapperUse(path, readFileSync(join(repoRoot, path), "utf-8")));
  }
  return uses;
}
