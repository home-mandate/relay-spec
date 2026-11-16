module github.com/home-mandate/relay-spec

go 1.27.4

require (
	github.com/home-mandate/spec v0.0.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	golang.org/x/net v0.62.0
)

require golang.org/x/text v0.43.0 // indirect

replace github.com/home-mandate/spec => /home/nexus/src/home-mandate-project/worktrees/spec-public-pkgs
