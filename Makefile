# SPDX-License-Identifier: Apache-2.0

# A go.work in a parent directory must not affect this module.
export GOWORK := off

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0
ACTIONLINT  := github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
GITLEAKS    := github.com/zricethezav/gitleaks/v8@v8.28.0

COVER_MIN      := 95
FUZZTIME       ?= 10m
# package:target; scheduled.yml and the release gate of release.yml fuzz this list (make fuzz-targets)
FUZZ_TARGETS   := internal/dnsq:FuzzCAA internal/tunnelclient:FuzzPROXY internal/frames:FuzzReadFrame \
	internal/frames:FuzzBind internal/tunnelcert:FuzzHomeIDOf internal/tunnelcert:FuzzCheckCSR \
	internal/request:FuzzVerifyRequest internal/ctlog:FuzzSCTList

.PHONY: check lint test cover vet modverify staticcheck vulncheck actionlint secrets hooks fuzz fuzz-one fuzz-targets manifest

## check: everything that must be green before a commit, except lint
check: modverify vet staticcheck cover vulncheck

## lint: the workflows (actionlint) and the whole history for secrets (gitleaks)
lint: actionlint secrets

test:
	go test -race ./...

cover:
	go test -race -coverprofile=cover.out ./...
	@go tool cover -func=cover.out | awk -v min=$(COVER_MIN) '/^total:/ { sub("%", "", $$3); \
		if ($$3 + 0 < min) { print "Coverage " $$3 "% < " min "%"; exit 1 } else print "Coverage " $$3 "%" }'

vet:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed"; exit 1; }
	go vet ./...

## modverify: the module cache matches go.sum, and go mod tidy would change nothing
modverify:
	go mod verify
	go mod tidy -diff

staticcheck:
	go run $(STATICCHECK) ./...

vulncheck:
	go run $(GOVULNCHECK) ./...

actionlint:
	go run $(ACTIONLINT)

secrets:
	go run $(GITLEAKS) git --redact --no-banner .

## hooks: once per clone, gitleaks on the staged changes before every commit
hooks:
	git config core.hooksPath .githooks

## manifest: rewrite conformance/manifest.json after changing schemas, examples or cases;
## the tests (make cover) check it
manifest:
	go run ./tools/vectors manifest

## fuzz: each target for FUZZTIME, e.g. make fuzz FUZZTIME=30s
fuzz:
	@for spec in $(FUZZ_TARGETS); do \
		$(MAKE) --no-print-directory fuzz-one FUZZ=$$spec || exit 1; \
	done

## fuzz-one: one target for FUZZTIME, e.g. make fuzz-one FUZZ=internal/frames:FuzzBind FUZZTIME=30s
fuzz-one:
	@spec='$(FUZZ)'; pkg=$${spec%%:*}; target=$${spec#*:}; \
	if [ -z "$$spec" ] || [ "$$pkg" = "$$spec" ]; then echo "FUZZ=package:target is needed"; exit 2; fi; \
	go test ./$$pkg/ -run '^$$' -fuzz "^$$target\$$" -fuzztime $(FUZZTIME)

## fuzz-targets: the targets, one package:target per line; the workflows build their lists from it
fuzz-targets:
	@printf '%s\n' $(FUZZ_TARGETS)
