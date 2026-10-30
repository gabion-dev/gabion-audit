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

The file's shape is checked before anything is judged: a misspelled field is an error, not "nothing declared".

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

## License

Business Source License 1.1 — see `LICENSE`.
