// src/config.ts
/**
 * The audit's file in a repository, `gabion-audit.json` at its root: the
 * releases the repository pins in files no manifest describes, the npm
 * trees whose advisories are judged, and the deviations it keeps on
 * purpose — each with its reason and the event that ends it.
 *
 * Plain JSON, so a repository of any language can carry it. Its shape is
 * checked before anything is judged: a misspelled field would otherwise
 * read as "nothing declared" and turn a kept deviation into a refusal, or
 * a pin into nothing judged at all.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

export const CONFIG_FILE = "gabion-audit.json";

const text = z.string().min(1);

const pinSource = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("github-releases"),
    repository: text,
    /** The tag of a release; its first capture group is the version. */
    tagPattern: text.default("^v?(\\d.*)$"),
  }),
  z.strictObject({
    kind: z.literal("github-tags"),
    repository: text,
    tagPattern: text.default("^v?(\\d.*)$"),
  }),
  z.strictObject({ kind: z.literal("npm"), package: text }),
  z.strictObject({ kind: z.literal("crates"), crate: text }),
  z.strictObject({ kind: z.literal("maven"), coordinate: text }),
  z.strictObject({
    kind: z.literal("listing"),
    url: text,
    /** A version the page names; its first capture group is the version. */
    pattern: text,
  }),
]);

export type PinSource = z.infer<typeof pinSource>;

/**
 * A release pinned in a file no manifest describes — a version variable in
 * a build script. `pattern` finds it; its first capture group is the
 * version. Every file named must contain it exactly once: a pin the
 * pattern no longer finds is an error, not a pin judged by nothing.
 */
const pin = z.strictObject({
  name: text,
  files: z.array(text).min(1),
  pattern: text,
  source: pinSource,
  /** How a newer release reaches the pin — said in the report next to the lag. */
  takeBy: text,
});

export type Pin = z.infer<typeof pin>;

const liftCondition = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("requirer-admits"), package: text }),
  z.strictObject({ kind: z.literal("follows-use"), source: text, name: text }),
]);

const acceptedLag = z.strictObject({
  source: text,
  name: text,
  heldLine: text,
  coversLatestLine: text,
  reason: text,
  reviewWhen: text,
  liftedWhen: liftCondition.optional(),
});

const acceptedAdvisory = z.strictObject({
  tree: text,
  package: text,
  advisory: text,
  reason: text,
  reviewWhen: text,
});

const advisoryTree = z.strictObject({
  name: text,
  directory: text,
  args: z.array(text).default([]),
});

export const configSchema = z.strictObject({
  $schema: z.string().optional(),
  pins: z.array(pin).default([]),
  advisoryTrees: z.array(advisoryTree).default([]),
  acceptedLags: z.array(acceptedLag).default([]),
  acceptedAdvisories: z.array(acceptedAdvisory).default([]),
});

export type AuditConfig = z.infer<typeof configSchema>;

/** The repository's audit file, checked; an empty configuration where it has none. */
export function readConfig(root: string): AuditConfig {
  const path = join(root, CONFIG_FILE);
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return configSchema.parse({});
    throw error;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`${CONFIG_FILE}: not JSON (${error instanceof Error ? error.message : String(error)})`);
  }
  const checked = configSchema.safeParse(parsed);
  if (!checked.success) {
    const problems = checked.error.issues
      .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("; ");
    throw new Error(`${CONFIG_FILE}: ${problems}`);
  }
  return checked.data;
}
