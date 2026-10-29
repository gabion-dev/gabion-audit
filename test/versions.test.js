// test/versions.test.js
// The ordering rule every source is compared by.

import assert from "node:assert/strict";
import { test } from "node:test";
import { compareVersions, isOnLine, lineOf, newestOf } from "../dist/index.js";

test("numeric segments order numerically, missing ones count as zero", () => {
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0);
  assert.equal(compareVersions("25", "25.0.0"), 0);
});

test("a pre-release orders below its release, Maven release qualifiers do not", () => {
  assert.ok(compareVersions("2.0.0-rc.1", "2.0.0") < 0);
  assert.ok(compareVersions("2.0.0-rc.2", "2.0.0-rc.10") < 0);
  assert.equal(compareVersions("5.3.0.Final", "5.3.0"), 0);
});

test("a version the rule cannot read is an error, not a guess", () => {
  assert.throws(() => compareVersions("latest", "1.0.0"), /can order/);
});

test("lines are prefixes of the numeric core", () => {
  assert.ok(isOnLine("0.8.22", "0.8"));
  assert.ok(!isOnLine("1.2.3", "0.8"));
  assert.equal(lineOf("24.19.2", "26"), "24");
});

test("newestOf skips pre-releases unless asked and versions it cannot read", () => {
  assert.equal(newestOf(["1.0.0", "2.0.0-beta.1", "nightly"], false), "1.0.0");
  assert.equal(newestOf(["1.0.0", "2.0.0-beta.1"], true), "2.0.0-beta.1");
});
