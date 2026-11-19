# Contributing

The Home-Mandate Relay Specification is meant to be implemented by anyone: operators who run a
relay, and gateways that use one. Changes are judged by that goal first, and by whether a
household can still trust a relay it does not control.

## Principles

1. **The specification is the truth.** If the reference code disagrees with the text, the code
   is wrong. If the text is unclear, the text is clarified first, then a conformance case is
   added, then the code is changed.
2. **The operator is not trusted with content.** No change may let an operator read or change
   what passes between an agent and a gateway, or what a household allows. Where an operator
   could still do harm, Section 9 says so.
3. **Every operator obligation can be met with standard tools**, and everything that can be
   checked from outside is checked by `relay-conformance` (Section 8).
4. **Everything normative is machine-readable** and usable without the Go code in this
   repository.
5. **The core comes first.** Rules that hold for every gateway reached from outside belong in
   Section 11.7 of the [Home-Mandate Specification](https://github.com/home-mandate/spec); this
   specification builds on them.

## Making a change

- Open an issue that describes the problem before a larger change.
- Every change to a rule comes with new or changed conformance cases. A bug report is most
  useful as a failing case.
- After changing a schema, an example or a conformance file run `make manifest`.
- `make check` and `make lint` must pass.
- When what runs in CI: a push to a branch runs `make check` and `make lint`; a pull request
  against main or a release branch additionally runs short fuzzing, which replays the inputs
  earlier runs found and gives every target 15 seconds; nothing runs after the merge.
  Independent of changes, govulncheck runs every night, and every fuzz target runs for ten
  minutes on Wednesday and Saturday and keeps what it finds; a failure opens an issue. A
  release candidate is fuzzed for 20 minutes per target before it can become the version.
- Until the freeze (RELAY-v0 Section 11), a minor version may change anything; the Changelog
  says what changed and what implementations have to do.
- Security problems: see `SECURITY.md`, not a public issue.

## Licenses

By contributing you agree that your contribution is licensed as the file it changes:
`RELAY-*.md` and `cas.md` under CC BY 4.0 (`LICENSE-docs`), everything else under Apache 2.0
(`LICENSE`).

## Governance

Who decides what is in the organization's
[governance](https://github.com/home-mandate/.github/blob/main/GOVERNANCE.md): until v1.0 I edit
the specification, in public pull requests, guided by the principles above, and implementers are
heard before an incompatible change. The organization's
[contributing rules](https://github.com/home-mandate/.github/blob/main/CONTRIBUTING.md) and
[code of conduct](https://github.com/home-mandate/.github/blob/main/CODE_OF_CONDUCT.md) apply here
too; what implementations keep is in
[IMPLEMENTATIONS.md](https://github.com/home-mandate/.github/blob/main/IMPLEMENTATIONS.md).
