# SPDX-License-Identifier: Apache-2.0

# A go.work in a parent directory must not affect this module.
export GOWORK := off

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0
ACTIONLINT  := github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
GITLEAKS    := github.com/zricethezav/gitleaks/v8@v8.28.0

COVER_MIN      := 95
FUZZTIME       ?= 10m
# package:target; the long fuzzing of scheduled.yml builds its matrix from this list (make fuzz-targets)
FUZZ_TARGETS   := internal/dnsq:FuzzCAA internal/tunnelclient:FuzzPROXY internal/frames:FuzzReadFrame \
	internal/frames:FuzzBind internal/tunnelcert:FuzzHomeIDOf internal/tunnelcert:FuzzCheckCSR

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

# Temporary (2026-10-09): staticcheck v0.8.1 cannot read Go 1.27's export data
# (dominikh/go-tools#1832). A run whose only output is that error (and module downloads)
# counts as a warning; any other output still fails. Remove once a compatible staticcheck
# release is pinned.
STATICCHECK_EXPORT_DATA := export data version 5 is greater than maximum supported version 4
staticcheck:
	@out=$$(go run $(STATICCHECK) ./... 2>&1); status=$$?; \
	if [ $$status -ne 0 ] && echo "$$out" | grep -qF "$(STATICCHECK_EXPORT_DATA)" && \
	   ! echo "$$out" | grep -vF -e "$(STATICCHECK_EXPORT_DATA)" -e "exit status" -e "go: downloading " | grep -q .; then \
		msg="staticcheck skipped: $(STATICCHECK) cannot read this Go version's export data (dominikh/go-tools#1832)"; \
		if [ -n "$$GITHUB_ACTIONS" ]; then echo "::warning::$$msg"; else echo "WARNING: $$msg"; fi; \
		exit 0; \
	fi; \
	[ -z "$$out" ] || echo "$$out"; exit $$status

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

## fuzz-targets: the targets, one package:target per line; the matrix of the long fuzzing is built from it
fuzz-targets:
	@printf '%s\n' $(FUZZ_TARGETS)
