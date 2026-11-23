<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Certificate authorities for relays (informative)

This list helps gateways and relay operators choose a certificate authority (CA) for the server
certificates of public names (RELAY-v0 Section 6.6). It is informative: conformance does not
depend on it, and a CA that is not listed but meets both conditions below may be used just as
well.

A CA is listed when, as far as public sources show,

1. it submits **every** certificate it issues to Certificate Transparency logs, so that a
   gateway's monitoring sees it (RELAY-v0 Section 6.7); and
2. it **enforces** the CAA parameters `accounturi` and `validationmethods` of RFC 8657, so that
   only the gateway's ACME account can obtain a certificate, and only through DNS (RELAY-v0
   Sections 5.6, 6.3, 6.4).

| CA | `caa_identity` | Account URI prefix | Logs every certificate | Enforces `accounturi`, `validationmethods` | Checked |
|---|---|---|---|---|---|
| Let's Encrypt | `letsencrypt.org` | `https://acme-v02.api.letsencrypt.org/acme/acct/` | "Let's Encrypt submits all certificates we issue to CT logs." ([CT logs](https://letsencrypt.org/docs/ct-logs/)) | documented in [CAA](https://letsencrypt.org/docs/caa/); checked at every issuance by Boulder ([`va/caa.go`](https://github.com/letsencrypt/boulder/blob/main/va/caa.go)) | 2026-10-20 |

The account URI prefix is the form of the URI of an ACME account at that CA (RFC 8555 Section
7.3); the test tool of RELAY-v0 Section 8.3 uses it, with a number that no account has, to report
an account that belongs to nobody.

The class `issuance` of the test tool (RELAY-v0 Section 8.3) creates real accounts and orders
certificates. It uses the CA's test environment unless it is asked for the production
environment, and needs both ACME endpoints:

| CA | Environment | ACME directory | Account URI prefix |
|---|---|---|---|
| Let's Encrypt | production | `https://acme-v02.api.letsencrypt.org/directory` | `https://acme-v02.api.letsencrypt.org/acme/acct/` |
| Let's Encrypt | test ([staging](https://letsencrypt.org/docs/staging-environment/)) | `https://acme-staging-v02.api.letsencrypt.org/directory` | `https://acme-staging-v02.api.letsencrypt.org/acme/acct/` |

The test environment enforces CAA as production does, but its certificates go to test logs that
no public log list contains, so the tool checks Certificate Transparency only in production.

To propose a CA, open an issue with public sources for both conditions. A CA is removed when a
source shows that it no longer meets one of them; operators then remove it from `acme_cas`, and
gateways move to another CA in `acme_cas` as RELAY-v0 Section 6.6 describes.
