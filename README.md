# gabion-audit

Checks a repository's pinned dependencies against their newest releases and known advisories. Only a lag or an advisory without a declared reason fails — and a declaration that no longer matches anything fails too, so an excuse cannot outlive its cause.

## What it judges

- **npm** — the direct dependencies of every workspace in `package-lock.json`, at the release the lock file resolves.
- **Cargo** — the direct dependencies of every workspace member, as `cargo metadata --locked` resolves them; compared with crates.io.
- **Rust** — the release `rust-toolchain.toml` pins, against the current stable release.
- **Gradle** — plugins, `"group:artifact:version"` literals and the Java toolchain of every tracked `*.gradle.kts`, and the release each wrapper runs. A version written in a form the audit cannot read is an error, not a skip.
- **GitHub Actions** — every `uses:` of the repository's workflows and composite actions. A major tag (`@v7`) is current while the newest release is on that major.
- **Pins** — versions in files no manifest describes, such as a variable in a build script, declared in `gabion-audit.json`.
- **Advisories** — `npm audit` over the npm trees `gabion-audit.json` names.

A source that does not answer leaves its dependencies unjudged, never current.

## Usage

```sh
npx gabion-audit [repository directory]
```

Exit codes: `0` — nothing undeclared; `1` — something undeclared, a dead declaration, or an inventory that could not be read; `2` — something could not be judged. Set `GITHUB_TOKEN` where many GitHub releases are read: unauthenticated, the GitHub API answers sixty requests an hour.

## gabion-audit.json

```json
{
  "pins": [
    {
      "name": "libsrtp",
      "files": ["build/build.sh"],
      "pattern": "^LIBSRTP_VERSION=\"([^\"]+)\"$",
      "source": { "kind": "github-releases", "repository": "cisco/libsrtp" },
      "takeBy": "the version and checksum in build/build.sh"
    }
  ],
  "advisoryTrees": [{ "name": "root", "directory": ".", "args": ["--omit=dev"] }],
  "acceptedLags": [
    {
      "source": "crates",
      "name": "schemars",
      "heldLine": "0.8",
      "coversLatestLine": "1",
      "reason": "typify-impl 0.8.0 requires schemars ^0.8.22",
      "reviewWhen": "a typify release that accepts schemars 1",
      "liftedWhen": { "kind": "requirer-admits", "package": "typify-impl" }
    }
  ],
  "acceptedAdvisories": []
}
```

- A **pin** is found by `pattern` (its first capture group is the version) exactly once in each file. Sources: `github-releases`, `github-tags` (with an optional `tagPattern`), `npm`, `crates`, `maven`, `listing` (a page and a pattern).
- An **accepted lag** holds a dependency on `heldLine` while the newest release lies on `coversLatestLine`. A use on another line, or a newest release on another line, is a case the reason was not written for, and fails. Inside the held line the use must be on its newest release.
- `liftedWhen` names an event a machine can observe: `requirer-admits` — the newest release of the named npm package or crate accepts the newest release of the held one; `follows-use` — the dependency follows another use of the repository and is justified while that use stays on the held line.
- An **accepted advisory** names the tree, the package and the advisory address exactly as `npm audit` reports it.

## As a library

A repository that keeps some pins in its own code passes them in, with the sources they come from, and they are judged under one report:

```ts
import { audit, EXIT_CODE } from "gabion-audit";

const result = await audit({
  root: process.cwd(),
  extraUses: () => [{ source: "engine", name: "valkey", version: "9.1.2", site: "engine-versions.ts" }],
  sources: { engine: { label: "engine", catalog: async () => ({ versions: ["9.1.2"] }), takeBy: () => "the pin" } },
});
console.log(result.text);
process.exit(EXIT_CODE[result.verdict]);
```

## License

Business Source License 1.1 — see `LICENSE`.
