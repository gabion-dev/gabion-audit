// test/audit.test.js
// The judgement of the audit against an npm the test provides: every
// outcome a tree and a declaration can reach, without the network. The
// audit spawns `npm` by name, so a script of that name first on PATH
// answers for the registry, by the directory it is asked about.

import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { audit, parseConfig } from "../dist/index.js";

const root = mkdtempSync(join(tmpdir(), "gabion-audit-test-"));
const bin = join(root, "bin");
const originalPath = process.env["PATH"];

// Trees answer by their directory name: "clean" reports nothing, "lodash"
// reports one advisory in lodash, "broken" is an npm that could not run.
const FAKE_NPM = `#!/bin/sh
case "$(basename "$PWD")" in
  clean) echo '{"vulnerabilities":{}}' ;;
  lodash) echo '{"vulnerabilities":{"lodash":{"via":[{"name":"lodash","url":"https://github.com/advisories/GHSA-test","severity":"high","title":"Prototype pollution"}]},"app":{"via":["lodash"]}}}'; exit 1 ;;
  *) echo "npm ERR! not a tree" >&2; exit 2 ;;
esac
`;

before(() => {
  mkdirSync(bin);
  writeFileSync(join(bin, "npm"), FAKE_NPM);
  chmodSync(join(bin, "npm"), 0o755);
  for (const tree of ["clean", "lodash", "broken"]) mkdirSync(join(root, tree));
  process.env["PATH"] = `${bin}:${originalPath ?? ""}`;
});

after(() => {
  process.env["PATH"] = originalPath;
  rmSync(root, { recursive: true, force: true });
});

const config = (advisoryTrees = [], acceptedAdvisories = []) => ({ advisoryTrees, acceptedAdvisories });
const tree = (name, directory = name) => ({ name, directory, args: [] });
const declaration = (extra = {}) => ({
  tree: "lodash",
  package: "lodash",
  advisory: "https://github.com/advisories/GHSA-test",
  reason: "kept for the test",
  reviewWhen: "never",
  ...extra,
});

test("a tree without advisories passes", async () => {
  const result = await audit({ root, config: config([tree("clean")]) });
  assert.equal(result.verdict, "passed");
  assert.match(result.text, /1 of 1 trees audited, 0 advisories/);
});

test("an undeclared advisory is refused and named with its address", async () => {
  const result = await audit({ root, config: config([tree("lodash")]) });
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /lodash — high, Prototype pollution \(https:\/\/github.com\/advisories\/GHSA-test\)/);
});

test("a package listed only as the effect of another's advisory is not repeated", async () => {
  const result = await audit({ root, config: config([tree("lodash")]) });
  assert.equal(result.text.split("\n").filter((line) => line.startsWith("  ✗")).length, 1);
});

test("a declared advisory is accepted with its reason", async () => {
  const result = await audit({ root, config: config([tree("lodash")], [declaration()]) });
  assert.equal(result.verdict, "passed");
  assert.match(result.text, /declared: kept for the test/);
});

test("a declaration npm audit no longer reports is dead", async () => {
  const result = await audit({ root, config: config([tree("lodash", "clean")], [declaration()]) });
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /no longer reports — remove the declaration/);
});

test("a declaration naming a tree that is not audited is dead", async () => {
  const result = await audit({ root, config: config([tree("clean")], [declaration({ tree: "elsewhere" })]) });
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /no audited tree has that name/);
});

test("an npm that cannot answer leaves the tree unjudged, not clean", async () => {
  const result = await audit({ root, config: config([tree("broken")]) });
  assert.equal(result.verdict, "unable");
  assert.match(result.text, /\? broken tree: npm audit/);
});

test("a tree the caller prepares is judged and disposed of", async () => {
  let disposed = false;
  const result = await audit({
    root,
    config: config(),
    advisoryTrees: [{ name: "prepared", directory: () => ({ directory: join(root, "clean"), dispose: () => (disposed = true) }) }],
  });
  assert.equal(result.verdict, "passed");
  assert.ok(disposed);
});

test("a refusal outranks an inability, and a caller's section is reported first", async () => {
  const result = await audit({
    root,
    config: config([tree("broken")]),
    sections: [{ title: "Policy", findings: [{ outcome: "refused", text: "a forced version is missing" }], passed: "agreed" }],
  });
  assert.equal(result.verdict, "refused");
  assert.ok(result.text.startsWith("Policy: agreed"));
});

test("an audit with nothing to judge is refused, not passed by silence", async () => {
  const result = await audit({ root, config: config() });
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /no npm tree is named/);
});

test("the audit file's shape is checked before anything is judged", () => {
  assert.throws(() => parseConfig({ advisoryTrees: [{ name: "x" }] }), /advisoryTrees\[0\]\.directory: expected a non-empty string/);
  assert.throws(() => parseConfig({ acceptedAdvisories: [{ tree: "x", package: "y", advisory: "z", reason: "r", reviewWhen: "w", extra: 1 }] }), /unknown field/);
  assert.throws(() => parseConfig({ pins: [] }), /no longer judges freshness/);
  assert.throws(() => parseConfig({ acceptedVulnerabilities: [{ scope: "production", purl: "ognl", advisory: "GHSA-x", reason: "r", reviewWhen: "w" }] }), /purl: expected a package URL with its version/);
  assert.deepEqual(parseConfig({}), { advisoryTrees: [], acceptedAdvisories: [], acceptedVulnerabilities: [] });
});
