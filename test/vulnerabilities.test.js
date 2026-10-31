// test/vulnerabilities.test.js
// The judgement of a vulnerability scan: an OSV-Scanner report read into
// findings per scope, declarations matched by any identifier of a
// bulletin, and the two ways a declaration dies.

import assert from "node:assert/strict";
import { test } from "node:test";
import { audit, judgeVulnerabilities, readOsvScannerReport } from "../dist/index.js";

// One Maven composition with one bulletin that has a GHSA and a CVE, and
// one npm lock file with a bulletin that has no fixed release.
const REPORT = {
  results: [
    {
      source: { path: "/project/backend/build/reports/cyclonedx/application.cdx.json", type: "sbom" },
      packages: [
        {
          package: { name: "ognl:ognl", version: "3.3.4", ecosystem: "Maven", purl: "pkg:maven/ognl/ognl@3.3.4" },
          vulnerabilities: [
            {
              id: "GHSA-crwc-vw2r-qr6m",
              aliases: ["CVE-2026-113730"],
              summary: "OGNL block list bypass",
              affected: [{ package: { ecosystem: "Maven", name: "ognl:ognl" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.4.13" }] }] }],
            },
          ],
          groups: [{ ids: ["GHSA-crwc-vw2r-qr6m"], aliases: ["CVE-2026-113730", "GHSA-crwc-vw2r-qr6m"], max_severity: "5.6" }],
        },
      ],
    },
    {
      source: { path: "/project/package-lock.json", type: "lockfile" },
      packages: [
        {
          package: { name: "minimatch", version: "10.2.6", ecosystem: "npm", purl: "pkg:npm/minimatch@10.2.6" },
          vulnerabilities: [{ id: "GHSA-g3hv-75wg-m249", aliases: [], summary: "globparts amplification", affected: [] }],
          groups: [{ ids: ["GHSA-g3hv-75wg-m249"], aliases: ["GHSA-g3hv-75wg-m249"], max_severity: "" }],
        },
        {
          package: { name: "semver", version: "7.6.0", ecosystem: "npm", purl: "pkg:npm/semver@7.6.0" },
          vulnerabilities: [],
          groups: [],
        },
      ],
    },
  ],
};

const scopeOf = (source) => (source.path.endsWith(".cdx.json") ? "production" : "development");
const reported = () => readOsvScannerReport(REPORT, scopeOf);
const judged = (judgedScopes = ["production", "development"]) => ({ reported: reported(), judgedScopes });
const config = (acceptedVulnerabilities = []) => ({ advisoryTrees: [], acceptedAdvisories: [], acceptedVulnerabilities });
const declaration = (extra = {}) => ({
  scope: "production",
  purl: "pkg:maven/ognl/ognl@3.3.4",
  advisory: "CVE-2026-113730",
  reason: "kept for the test",
  reviewWhen: "never",
  ...extra,
});

test("a report is read into one finding per component and bulletin, with its scope and fixed releases", () => {
  const findings = reported();
  assert.equal(findings.length, 2);
  const [ognl, minimatch] = findings;
  assert.equal(ognl.scope, "production");
  assert.equal(ognl.advisory, "GHSA-crwc-vw2r-qr6m");
  assert.deepEqual(ognl.identifiers, ["GHSA-crwc-vw2r-qr6m", "CVE-2026-113730"]);
  assert.deepEqual(ognl.fixedVersions, ["3.4.13"]);
  assert.equal(ognl.severity, "5.6");
  assert.equal(minimatch.scope, "development");
  assert.deepEqual(minimatch.fixedVersions, []);
});

test("a report of another shape is refused, not read as empty", () => {
  assert.throws(() => readOsvScannerReport({ nothing: true }, scopeOf), /results: expected the results array/);
  assert.throws(
    () => readOsvScannerReport({ results: [{ source: { path: "x", type: "sbom" }, packages: [{ package: { name: "a", version: "1", ecosystem: "npm", purl: "pkg:npm/a@1" }, vulnerabilities: [{ id: "X" }] }] }] }, scopeOf),
    /groups: expected the bulletin groups/,
  );
});

test("undeclared vulnerabilities are refused with scope, component, bulletin and fixed releases", async () => {
  const result = await audit({ root: ".", config: config(), vulnerabilities: judged() });
  assert.equal(result.verdict, "refused");
  assert.match(result.text, /production: pkg:maven\/ognl\/ognl@3\.3\.4 — GHSA-crwc-vw2r-qr6m \(CVE-2026-113730\), severity 5\.6, OGNL block list bypass; fixed in 3\.4\.13/);
  assert.match(result.text, /development: pkg:npm\/minimatch@10\.2\.6 — GHSA-g3hv-75wg-m249, globparts amplification; fixed in no release yet/);
  assert.match(result.text, /2 scopes judged \(production, development\), 2 vulnerabilities/);
});

test("a declaration matches a bulletin by any of its identifiers", async () => {
  const result = await audit({ root: ".", config: config([declaration()]), vulnerabilities: judged() });
  assert.match(result.text, /ognl@3\.3\.4 — GHSA-crwc-vw2r-qr6m .* — declared: kept for the test/);
  assert.equal(result.text.split("\n").filter((line) => line.startsWith("  ✗")).length, 1);
});

test("a declaration the scan no longer reports is dead", async () => {
  const result = await audit({ root: ".", config: config([declaration({ purl: "pkg:maven/ognl/ognl@3.4.0" })]), vulnerabilities: judged() });
  assert.match(result.text, /declares CVE-2026-113730 in pkg:maven\/ognl\/ognl@3\.4\.0 \(production scope\), which the scan no longer reports/);
});

test("a declaration naming a scope the run did not judge is dead", async () => {
  const result = await audit({ root: ".", config: config([declaration({ scope: "engine" })]), vulnerabilities: judged() });
  assert.match(result.text, /\(engine scope\), and no judged scope has that name/);
});

test("declarations are left alone when no scan was passed", async () => {
  const result = await audit({ root: ".", config: { ...config([declaration()]), advisoryTrees: [{ name: "x", directory: ".", args: [] }] } });
  assert.doesNotMatch(result.text, /Vulnerabilities \(OSV\)/);
});

test("a scan that reported nothing in a judged scope passes", async () => {
  const result = await audit({ root: ".", config: config(), vulnerabilities: { reported: [], judgedScopes: ["production"] } });
  assert.equal(result.verdict, "passed");
  assert.match(result.text, /1 scopes judged \(production\), 0 vulnerabilities/);
});

test("the structured judgement names the covering declaration and the dead ones", () => {
  const judgement = judgeVulnerabilities(judged(), [declaration(), declaration({ scope: "engine" }), declaration({ purl: "pkg:maven/ognl/ognl@3.4.0" })]);
  assert.equal(judgement.findings.length, 2);
  assert.equal(judgement.findings[0].declaration?.reason, "kept for the test");
  assert.equal(judgement.findings[1].declaration, null);
  assert.deepEqual(judgement.dead.map((entry) => entry.cause), ["scope-not-judged", "no-longer-reported"]);
});
