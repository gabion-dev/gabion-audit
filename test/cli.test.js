// test/cli.test.js
// The command line with a vulnerability scan: a report file judged under
// the scope the argument names, against the repository's declarations.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

const CLI = new URL("../dist/cli/gabion-audit.js", import.meta.url).pathname;
const root = mkdtempSync(join(tmpdir(), "gabion-audit-cli-"));

// One Cargo lock file with one bulletin.
const REPORT = {
  results: [
    {
      source: { path: "/repo/Cargo.lock", type: "lockfile" },
      packages: [
        {
          package: { name: "atomic-polyfill", version: "1.0.3", ecosystem: "crates.io", purl: "pkg:cargo/atomic-polyfill@1.0.3" },
          vulnerabilities: [{ id: "RUSTSEC-2023-0089", aliases: [], summary: "atomic-polyfill is unmaintained", affected: [] }],
          groups: [{ ids: ["RUSTSEC-2023-0089"], aliases: ["RUSTSEC-2023-0089"], max_severity: "" }],
        },
      ],
    },
  ],
};

const run = (directory, ...args) => spawnSync(process.execPath, [CLI, directory, ...args], { encoding: "utf-8" });

before(() => {
  writeFileSync(join(root, "cargo.json"), JSON.stringify(REPORT));
  mkdirSync(join(root, "undeclared"));
  mkdirSync(join(root, "declared"));
  writeFileSync(
    join(root, "declared", "gabion-audit.json"),
    JSON.stringify({
      acceptedVulnerabilities: [
        { scope: "cargo", purl: "pkg:cargo/atomic-polyfill@1.0.3", advisory: "RUSTSEC-2023-0089", reason: "not compiled for the targets we build", reviewWhen: "heapless 0.8 upstream" },
      ],
    }),
  );
});

after(() => {
  rmSync(root, { recursive: true, force: true });
});

test("a report judged under its scope refuses an undeclared finding", () => {
  const result = run(join(root, "undeclared"), "--osv-report", `${join(root, "cargo.json")}=cargo`);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /cargo: pkg:cargo\/atomic-polyfill@1\.0\.3 — RUSTSEC-2023-0089/);
});

test("a declared finding passes and is listed as declared", () => {
  const result = run(join(root, "declared"), "--osv-report", `${join(root, "cargo.json")}=cargo`);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /declared: not compiled for the targets we build/);
});

test("a report argument without a scope is a usage error", () => {
  const result = run(join(root, "declared"), "--osv-report", join(root, "cargo.json"));
  assert.equal(result.status, 2);
  assert.match(result.stderr, /needs <file>=<scope>/);
});
