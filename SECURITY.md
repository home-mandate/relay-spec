# Security

## Reporting a vulnerability

Please do **not** open a public issue for anything that could put a household at risk: a flaw in
the tunnel protocol, pairing and issuance, the rules for names, certificates and protection
levels, the operator obligations, the reference code or a conformance case that requires insecure
behavior.

Report it privately through this repository on GitHub: **Security → Report a vulnerability**
(GitHub private vulnerability reporting), or to security@home-mandate.org. We acknowledge within
72 hours and disclose in a coordinated manner. A flaw in the specification affects every operator
and gateway, so we inform known implementers before the fix is published.

## Scope

In scope: `RELAY-*.md`, `schema/`, `conformance/`, `examples/`, `cas.md`, `relay-conformance` and
the Go packages in this repository. Vulnerabilities in a relay or a gateway that implements the
specification belong to that product; if the cause is an ambiguity in the specification, report it
here as well. Rules for every gateway reached from outside (SPEC-v0 Section 11.7) belong to
[home-mandate/spec](https://github.com/home-mandate/spec/security).

## How fixes are made

Every fix starts with a conformance case that fails, then the text of the specification, then the
reference code. The Changelog in the specification names the change and what operators and
gateways have to do.

## Rules for the reference code

- Every decoder rejects malformed input with an error; it never panics, and it never allocates
  based on a length it has not validated.
- Never write stream tokens, certificates or private keys to a log.
- The default is to refuse. Whatever the specification does not explicitly allow is an error.
- New dependencies only with a justification in the pull request.
