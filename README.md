# gabion-audit

Judges the npm trees a repository's consumers install against known advisories. Only an advisory without a declared reason fails — and a declaration that no longer matches anything fails too, so an excuse cannot outlive its cause.

Whether a dependency is current is not judged here: Renovate proposes each newer release as a pull request, and a lag kept on purpose is a package rule of its configuration. The audit gates a release on what a bot cannot decide for the repository — a known vulnerability in the tree a consumer installs.

## What it judges

- **Advisories** — `npm audit` over the npm trees `gabion-audit.json` names, each in the form its consumers install it (`--omit=dev` for a published package).

A repository that names no tree is refused, not passed: an audit that judged nothing has audited nothing.

## Usage

```sh
npx gabion-audit [repository directory]
```

Exit codes: `0` — nothing undeclared; `1` — an undeclared advisory, a dead declaration, an audit file that cannot be read, or nothing to judge; `2` — something could not be judged (`npm audit` did not answer).

The package has no runtime dependencies: `npx` installs it alone, so a release-age policy of the machine (`min-release-age` in `.npmrc`) can be lifted for this one command without admitting any third-party code published yesterday.

## gabion-audit.json

```json
{
  "advisoryTrees": [{ "name": "package", "directory": ".", "args": ["--omit=dev"] }],
  "acceptedAdvisories": [
    {
      "tree": "package",
      "package": "example",
      "advisory": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
      "reason": "the vulnerable function is never reached: the package is used only to parse trusted input",
      "reviewWhen": "a release of example that fixes the advisory"
    }
  ]
}
```

- An **advisory tree** is a directory of the repository `npm audit` runs in, with the arguments consumers install it with.
- An **accepted advisory** names the tree, the package and the advisory address exactly as `npm audit` reports it, with the reason it is kept and the event that ends the reason.
- An **accepted vulnerability** (`acceptedVulnerabilities`) names a finding of a vulnerability scan the repository runs with the library below: the scope the caller judges (`production`, `development`, an engine, a pinned tool — the caller's names), the component as a package URL with its version (`pkg:maven/ognl/ognl@3.3.4`), any identifier of the bulletin (its GHSA, its CVE — aliases of one bulletin are one bulletin), the reason and the event that ends it. A component raised to a release the bulletin still covers is a new finding: the declaration named the old release and dies with it.

```json
{
  "acceptedVulnerabilities": [
    {
      "scope": "development",
      "purl": "pkg:npm/minimatch@10.2.6",
      "advisory": "GHSA-g3hv-75wg-m249",
      "reason": "a build-time tool parses patterns the repository writes itself",
      "reviewWhen": "a release of the linter that admits minimatch 11"
    }
  ]
}
```

**The event that ends a reason** (`reviewWhen`) is written in words or as a date. An event in words is judged by people and never ends by the clock. A date (ISO 8601 — `2026-12-01`, or a date with its time) ends the declaration: from that moment it covers nothing, and the advisory or the finding is refused again, naming the declaration that ended — fix it, or renew the declaration with a reason that still holds and a new date. A kept risk with a date has an end, not a reminder.

The file's shape is checked before anything is judged: a misspelled field is an error, not "nothing declared", and a `reviewWhen` written as a date that is no date (`2026-13-45`) is an error, not words.

## A vulnerability scan from the command line

A repository that scans its compositions itself (OSV-Scanner, `--format json`) hands the report to the command with the scope its findings belong to — the name a declaration in `gabion-audit.json` carries:

```sh
osv-scanner scan source --format json --output-file cargo.json -L Cargo.lock || [ $? -eq 1 ]
npx --yes gabion-audit@0.4.0 --osv-report cargo.json=cargo
```

One report per scope; several `--osv-report` arguments are judged together with the advisory trees of the file, under one verdict. A declaration of a scope no report names is dead.

## As a library

A repository that prepares a tree in its own code, or judges a policy of its own, passes them in and they are judged under one report:

```ts
import { audit, EXIT_CODE } from "gabion-audit";

const result = await audit({
  root: process.cwd(),
  sections: [{ title: "Policy", findings: [], passed: "the manifest agrees with the policy" }],
  advisoryTrees: [{ name: "runtime", directory: () => ({ directory: "/tmp/runtime-tree", dispose: () => {} }), args: ["--omit=dev"] }],
});
console.log(result.text);
process.exit(EXIT_CODE[result.verdict]);
```

### Vulnerability scans

A repository that scans its compositions, lock files or artifacts with [OSV-Scanner](https://google.github.io/osv-scanner/) passes the scan's JSON report, read into findings per scope, and every scope the scan covered — found or not, so a declaration for a scope the run did not judge is reported as dead rather than silently kept:

```js
import { audit, readOsvScannerReport } from "gabion-audit";

const reported = readOsvScannerReport(JSON.parse(scannerJson), (source) =>
  source.path.endsWith("application.cdx.json") ? "production" : "development");
const result = await audit({ root: ".", vulnerabilities: { reported, judgedScopes: ["production", "development"] } });
```

Findings are counted per component and bulletin, where a bulletin is the group the scanner forms of a record and its aliases. `judgeVulnerabilities` gives the same judgement structured — each finding with the declaration that covers it (or the one whose review date ended it), and the declarations that cover nothing — for a caller that renders it rather than prints the report; `isReviewDue` and `reviewDate` tell such a caller when a declaration's date comes. The command line judges npm trees only; vulnerability scans go through the library, because which file is which scope is the caller's knowledge.

## License

Business Source License 1.1 — see `LICENSE`.
