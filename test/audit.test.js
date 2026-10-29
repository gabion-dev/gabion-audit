// test/audit.test.js
// The judgement of the audit against sources the test defines: every
// outcome a use and a declaration can reach, without the network.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { audit, SourceUnavailable } from "../dist/index.js";

// An empty git repository: the inventory reads tracked files and finds
// none, so only the uses the test passes are judged.
const root = mkdtempSync(join(tmpdir(), "gabion-audit-test-"));
spawnSync("git", ["init", "--quiet"], { cwd: root });
after(() => rmSync(root, { recursive: true, force: true }));

const releases = { tool: ["1.0.0", "1.2.0", "2.0.0", "2.1.0"], action: ["6.0.0", "7.0.0", "7.1.2"] };

const sources = {
  test: {
    label: "test",
    catalog: async (use) => {
      if (use.name === "silent") throw new SourceUnavailable("no answer");
      return { versions: releases[use.name] ?? [] };
    },
    takeBy: () => "raise it",
  },
};

const config = (acceptedLags = []) => ({ pins: [], advisoryTrees: [], acceptedLags, acceptedAdvisories: [] });

const use = (name, version, extra = {}) => ({ source: "test", name, version, site: "test", ...extra });

async function run(uses, acceptedLags) {
  return audit({ root, config: config(acceptedLags), sources, extraUses: () => uses });
}

const lag = (extra = {}) => ({
  source: "test",
  name: "tool",
  heldLine: "1",
  coversLatestLine: "2",
  reason: "kept for the test",
  reviewWhen: "never",
  ...extra,
});

test("a use at the newest release passes", async () => {
  const result = await run([use("tool", "2.1.0")]);
  assert.equal(result.verdict, "passed");
});

test("an undeclared lag is refused and names the newest release", async () => {
  const result = await run([use("tool", "2.0.0")]);
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /newest 2\.1\.0/);
});

test("a declared lag on the newest release of its held line is accepted", async () => {
  const result = await run([use("tool", "1.2.0")], [lag()]);
  assert.equal(result.verdict, "passed");
  assert.match(result.text, /declared: kept for the test/);
});

test("a declared lag below the newest release of its held line is refused", async () => {
  const result = await run([use("tool", "1.0.0")], [lag()]);
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /1\.2\.0 is the newest release of that line/);
});

test("a use off the declared held line is a case the reason was not written for", async () => {
  const result = await run([use("tool", "2.0.0")], [lag()]);
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /judge it again/);
});

test("a declaration whose dependency is current is dead", async () => {
  const result = await run([use("tool", "2.1.0")], [lag({ heldLine: "2", coversLatestLine: "2" })]);
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /no use of it lags under this declaration any more/);
});

test("a declaration of a dependency the repository does not use is dead", async () => {
  const result = await run([], [lag()]);
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /uses no such dependency/);
});

test("a use pinned to a line is current while the newest release lies on it", async () => {
  assert.equal((await run([use("action", "7", { precision: "line" })])).verdict, "passed");
  assert.equal((await run([use("action", "6", { precision: "line" })])).verdict, "refused");
});

test("a source that does not answer leaves the use unjudged, not current", async () => {
  const result = await run([use("silent", "1.0.0")]);
  assert.equal(result.verdict, "unable");
});

test("follows-use: the lag is dead once the followed use leaves the held line", async () => {
  const follows = lag({ name: "types", liftedWhen: { kind: "follows-use", source: "test", name: "runtime" } });
  releases.types = ["1.5.0", "2.0.0"];
  releases.runtime = ["1.9.0", "2.0.0"];
  const held = await run([use("types", "1.5.0"), use("runtime", "1.9.0", { precision: "release" })], [follows]);
  assert.match(held.text, /declared: kept for the test/);
  const moved = await run([use("types", "1.5.0"), use("runtime", "2.0.0")], [follows]);
  assert.match(moved.text, /off the held line: move types with it/);
});

test("a use whose source is not defined is refused, not skipped", async () => {
  const result = await audit({
    root,
    config: config(),
    extraUses: () => [{ source: "nowhere", name: "x", version: "1.0.0", site: "test" }],
  });
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /no source defined for "nowhere"/);
});
