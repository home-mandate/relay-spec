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

Merges are not tagged one by one. A pre-release (`v0.1.0-alpha.1`) is tagged on `main` on
purpose, when implementers should look at a state.

## The release gate

After a release candidate is published, `release.yml` fuzzes every target of `FUZZ_TARGETS`
for 20 minutes, on top of the corpus the runs of `scheduled.yml` have collected. The job
`Release gate` succeeds only if all of them passed, and a version can only be tagged on a
commit whose release candidate has that job green.

## The core specification

This specification builds on the Home-Mandate Specification
([home-mandate/spec](https://github.com/home-mandate/spec)). Between releases, `go.mod` may require
a pseudo-version of its `main`. A tag needs a published release of it: `release.yml` refuses a
`go.mod` with a `replace` directive or with a requirement that is not a published release of
home-mandate/spec, because users of the module get exactly the version `go.mod` requires. The
lowest version of SPEC-v0 a version requires is stated at the top of `RELAY-v0.md`.

## Before a tag

- `make manifest` was run after a change to a schema, an example or a conformance file.
- `go.mod` requires a published release of home-mandate/spec, and the top of `RELAY-v0.md` names
  the lowest version of SPEC-v0 it needs. For a version that is a version of the core
  specification, not a release candidate: when the core's version follows its release
  candidate, a pull request moves `go.mod` to it and a new release candidate is tagged.
- A release candidate and a version have their entry in the changelog of `RELAY-v0.md`, moved
  out of "Unreleased" and without a date, before the first release candidate; `release.yml`
  refuses them otherwise.
- The dry run passes: it checks the tag without creating it.

```sh
# the release candidate, on the release branch
gh workflow run release.yml --ref release/0.1 -f tag=v0.1.0-rc.1   # dry run, publishes nothing
git switch release/0.1 && git pull
git tag -a v0.1.0-rc.1 -m "Home-Mandate Relay Specification v0.1.0-rc.1"
git push origin v0.1.0-rc.1

# the version, on the commit of the release candidate, after its gate and the test
gh workflow run release.yml --ref release/0.1 -f tag=v0.1.0
git tag -a v0.1.0 -m "Home-Mandate Relay Specification v0.1.0" v0.1.0-rc.1^{commit}
git push origin v0.1.0
```

The text of the release is generated and can be edited afterwards.

## After a patch

The patch's changelog entry goes to `RELAY-v0.md` on `main` too. Implementations and
home-mandate.org follow in their own pull requests.
