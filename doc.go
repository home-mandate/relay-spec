// SPDX-License-Identifier: Apache-2.0

// Package relay embeds the machine-readable files of the Home-Mandate Relay Specification
// (RELAY-v0.md): the schemas of the operator metadata and of the enrollment messages, their
// examples, and the conformance cases in conformance/ with their manifest. Its tests check
// them; the requests with internal/request, the metadata with internal/metadata. FS embeds the schemas, examples and cases, never conformance/keys,
// for the test tool cmd/relay-conformance and for implementations that test against exactly
// the version they depend on.
package relay
