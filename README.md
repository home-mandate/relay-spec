<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/home-mandate/.github/main/profile/assets/hm-lockup-dark.svg">
  <img src="https://raw.githubusercontent.com/home-mandate/.github/main/profile/assets/hm-lockup.svg" alt="Home-Mandate – AI is coming home. Decide what it may do." width="360">
</picture>

# Home-Mandate Relay Specification

How a gateway of the [Home-Mandate Specification](https://github.com/home-mandate/spec) in a
home, usually behind NAT, is reached by cloud agents through a **relay that anyone may run**,
without the operator being able to read or change what passes: the tunnel protocol, pairing and
issuance of certificates, public names and protection levels, Certificate Transparency and CAA
checks, and what an operator must and must not do. With conformance cases, a live test tool for
operators and Go reference code.

Status: released, not frozen; the newest version is the [latest
release](https://github.com/home-mandate/relay-spec/releases/latest). It requires the Home-Mandate
Specification v0.2.0 or later (Section 11.7 "Remote access" and the audit format `audit/v1` there;
RELAY-v0 Section 12 maps its `relay.*` events). Versions are the tags `vX.Y.Z` of this repository;
nothing is frozen before a relay and a gateway have worked together (RELAY-v0 Section 11).
Home-Mandate Cloud is the first operator to implement it, and Home-Mandate for Home Assistant the
first gateway.

## Testing an operator

An operator tests its own operation with `relay-conformance` (RELAY-v0 Section 8.3). Install the
tool of the newest release, or of the tag `vX.Y.Z` you test against; the report names the
version, and a claim of conformance names it too:

```sh
go install github.com/home-mandate/relay-spec/cmd/relay-conformance@latest
relay-conformance -help   # the call, the codes, the classes and the exit codes (exit 2)
relay-conformance -list   # every check with its section
```

Every release attaches `conformance-report.json`, the report of the same tool against the
reference of this repository, with an attestation of its build (`gh attestation verify
conformance-report.json -R home-mandate/relay-spec`).

## Contents

| Path | Contents | License |
|---|---|---|
| `RELAY-v0.md` | The specification | CC BY 4.0 |
| `cas.md` | Informative list of certificate authorities that log every certificate and enforce RFC 8657 | CC BY 4.0 |
| `schema/` | JSON Schemas of the operator metadata (section 3) and of the enrollment messages (section 5) | Apache 2.0 |
| `examples/` | Examples of the metadata and of the enrollment messages, each valid against its schema | Apache 2.0 |
| `conformance/enrollment-v0.json` | The order of the checks of an enrollment request (section 5.1), with the error the operator answers | Apache 2.0 |
| `conformance/jws-v0.json` | Requests of the Relay Specification (the JWS of sections 5.1 and 5.5) with the expected result: valid, malformed or bad-signature | Apache 2.0 |
| `conformance/metadata-v0.json` | Operator metadata (section 3) that a gateway accepts or rejects | Apache 2.0 |
| `conformance/csr-v0.json` | Certificate signing requests for tunnel certificates (section 5.4) that an operator accepts or refuses with `bad-csr` | Apache 2.0 |
| `conformance/certificate-v0.json` | Issued tunnel certificates (section 5.4), valid or invalid | Apache 2.0 |
| `conformance/frames-v0.json` | Frames of a control connection of the tunnel (sections 4.3, 4.4, 4.7), valid or an error | Apache 2.0 |
| `conformance/binding-v0.json` | First bytes of a data connection (section 4.5): bound or closed, and the tokens consumed | Apache 2.0 |
| `conformance/tls-v0.json` | TLS probes of tunnel connections (sections 4.1, 4.2) that the relay accepts or refuses | Apache 2.0 |
| `conformance/pairing-v0.json` | Pairing strings and whether a gateway accepts them (section 5.2) | Apache 2.0 |
| `conformance/pins-v0.json` | New pins announced to a gateway: stored or ignored (sections 4.7, 6.8) | Apache 2.0 |
| `conformance/proxy-v0.json` | PROXY headers as a gateway reads them (section 4.6) | Apache 2.0 |
| `conformance/destination-v0.json` | Addresses a gateway may connect to (section 3) | Apache 2.0 |
| `conformance/caa-v0.json` | Comparison of CAA records in the gateway's monitoring (sections 6.3, 6.7) | Apache 2.0 |
| `conformance/protection-level-v0.json` | Determining the protection level of an own-domain name (section 6.5) | Apache 2.0 |
| `conformance/keys/` | Test keys of the relay cases; the private parts are public | Apache 2.0 |
| `conformance/schema/` | JSON Schemas of the relay conformance files | Apache 2.0 |
| `conformance/manifest.json` | All machine-readable files of the Relay Specification with SHA-256 and number of cases; `make manifest` rewrites it | Apache 2.0 |
| `cmd/relay-conformance` | Live test of an operator against the conformance classes (RELAY-v0 Section 8) | Apache 2.0 |
| `cmd/relay-reference` | Runs that live test against the reference on the loopback; its report is attached to every release | Apache 2.0 |
| `internal/` | Reference code: operator, relay, DNS and gateway decisions that the tests run the cases and the live test against | Apache 2.0 |
| `tools/vectors` | Generates the conformance files that need keys and writes the manifest | Apache 2.0 |
| `*.go` (root) | Go package `relay`: the schemas, examples and cases embedded as `relay.FS()`, without the test keys | Apache 2.0 |

## Checks

Go 1.27.4. Tools are pinned in the `Makefile` and fetched with `go run`.

```sh
make hooks      # once: gitleaks on staged changes before every commit
make check      # module, format, vet, staticcheck, race tests with coverage ≥ 95 %, govulncheck
make lint       # actionlint and gitleaks over the whole history
make fuzz FUZZTIME=30s
make manifest   # after changing a schema, an example or a conformance file
```

## Related

- [home-mandate/spec](https://github.com/home-mandate/spec): the core specification, which this
  one builds on.
- [RELEASING.md](RELEASING.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md).
