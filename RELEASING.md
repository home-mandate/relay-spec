# Releasing the Relay Specification

The rules are the same for the whole organization:
[RELEASING.md](https://github.com/home-mandate/.github/blob/main/RELEASING.md). This page says
only what is particular to this repository.

## What is published

A version is the text, the schemas, the examples, the conformance cases, `relay-conformance` and
the reference code at a tag `vX.Y.Z`; the Go module proxy serves the module
`github.com/home-mandate/relay-spec` from the tag. A tag runs `.github/workflows/release.yml`,
which creates the GitHub release as a draft; `conformance-report.yml` runs the live test of
`relay-conformance` against the reference operator, relay and DNS (`cmd/relay-reference`) and
attaches the attested report to the draft, and the draft is published only with the report
attached. A published release is immutable. A run that fails before that leaves a draft, and the
version needs a new tag; the Go module proxy may serve the failed tag anyway.

Merges are not tagged one by one. A pre-release (`v0.1.0-alpha.1`) is tagged on purpose, when
implementers should look at a state.

## The core specification

This specification builds on the Home-Mandate Specification
([home-mandate/spec](https://github.com/home-mandate/spec)). Between releases, `go.mod` may require
a pseudo-version of its `main`. A tag needs a published release of it: `release.yml` refuses a
`go.mod` with a `replace` directive or with a requirement that is not a published release of
home-mandate/spec, because users of the module get exactly the version `go.mod` requires. The
lowest version of SPEC-v0 a version requires is stated at the top of `RELAY-v0.md`.

## Before a tag

- `make check`, `make lint` and `make fuzz` pass.
- `make manifest` was run after a change to a schema, an example or a conformance file.
- `go.mod` requires a published release of home-mandate/spec, and the top of `RELAY-v0.md` names
  the lowest version of SPEC-v0 it needs.
- A version without a suffix has its entry in the changelog of `RELAY-v0.md`, moved out of
  "Unreleased"; `release.yml` refuses it otherwise.

```sh
git switch main && git pull   # for a patch: release/X.Y
git tag -a v0.1.0-alpha.1 -m "Home-Mandate Relay Specification v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
```

The text of the release is generated and can be edited afterwards.

## After a patch

The patch's changelog entry goes to `RELAY-v0.md` on `main` too. Implementations and
home-mandate.org follow in their own pull requests.
