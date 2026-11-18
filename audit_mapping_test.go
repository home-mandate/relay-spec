// SPDX-License-Identifier: Apache-2.0

package relay_test

import (
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	spec "github.com/home-mandate/spec"
)

// auditEvent is what audit/v1 of SPEC-v0 allows for one relay.* event: the members of relay
// besides operator, and the values of those members that are an enumeration.
type auditEvent struct {
	members []string
	values  map[string][]string
}

// relayProps is the part of the audit/v1 schema that describes the member relay.
type relayProps struct {
	PropertyNames struct {
		Enum []string `json:"enum"`
	} `json:"propertyNames"`
	Properties map[string]struct {
		Enum []string `json:"enum"`
	} `json:"properties"`
}

// relayAuditEvents reads the relay.* events from the audit/v1 schema of the core module.
func relayAuditEvents(t *testing.T) map[string]auditEvent {
	t.Helper()
	var schema struct {
		Properties struct {
			Relay relayProps `json:"relay"`
		} `json:"properties"`
		AllOf []struct {
			If struct {
				Properties struct {
					Event struct {
						Const string `json:"const"`
					} `json:"event"`
				} `json:"properties"`
			} `json:"if"`
			Then struct {
				Properties struct {
					Relay *relayProps `json:"relay"`
				} `json:"properties"`
			} `json:"then"`
		} `json:"allOf"`
	}
	data, err := fs.ReadFile(spec.FS(), spec.AuditV1SchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	events := map[string]auditEvent{}
	for _, rule := range schema.AllOf {
		name, relay := rule.If.Properties.Event.Const, rule.Then.Properties.Relay
		if !strings.HasPrefix(name, "relay.") || relay == nil {
			continue
		}
		e := auditEvent{values: map[string][]string{}}
		for _, m := range relay.PropertyNames.Enum {
			if m == "operator" {
				continue
			}
			e.members = append(e.members, m)
			values := schema.Properties.Relay.Properties[m].Enum
			if own, ok := relay.Properties[m]; ok && len(own.Enum) > 0 {
				values = own.Enum
			}
			if len(values) > 0 {
				e.values[m] = values
			}
		}
		events[name] = e
	}
	// Every relay.* event that the schema names anywhere has a rule of its own.
	for _, name := range regexp.MustCompile(`"(relay\.[a-z_]+)"`).FindAllStringSubmatch(string(data), -1) {
		if _, ok := events[name[1]]; !ok {
			t.Errorf("audit/v1 names %s without a rule for its members", name[1])
		}
	}
	if len(events) == 0 {
		t.Fatal("audit/v1 defines no relay.* event")
	}
	return events
}

// backticked finds the names in a cell of the table.
var backticked = regexp.MustCompile("`([a-z_]+)`")

// mappingRows reads the table of RELAY-v0 Section 12: for each event its members and its row.
func mappingRows(t *testing.T) map[string][2]string {
	t.Helper()
	data, err := os.ReadFile("RELAY-v0.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "\n## 12. Audit events of a gateway\n")
	if !ok {
		t.Fatal("RELAY-v0 has no Section 12 that maps the audit events")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	_, table, ok := strings.Cut(section, "| Event | Members | Recorded when |\n|---|---|---|\n")
	if !ok {
		t.Fatal("Section 12 has no table of events")
	}
	table, _, _ = strings.Cut(table, "\n\n")
	rows := map[string][2]string{}
	for _, line := range strings.Split(table, "\n") {
		cells := strings.Split(line, " | ")
		if len(cells) != 3 {
			t.Fatalf("row with %d cells: %s", len(cells), line)
		}
		name := strings.Trim(strings.TrimPrefix(cells[0], "| "), "`")
		if _, dup := rows[name]; dup {
			t.Errorf("Section 12 maps %s twice", name)
		}
		rows[name] = [2]string{strings.TrimSpace(cells[1]), cells[2]}
	}
	return rows
}

// TestSection12MapsEveryRelayAuditEvent: RELAY-v0 Section 12 maps exactly the relay.* events of
// audit/v1, names exactly their members besides operator, and says when each value of an
// enumerated member is recorded.
func TestSection12MapsEveryRelayAuditEvent(t *testing.T) {
	events, rows := relayAuditEvents(t), mappingRows(t)
	if got, want := slices.Sorted(maps.Keys(rows)), slices.Sorted(maps.Keys(events)); !slices.Equal(got, want) {
		t.Fatalf("Section 12 maps %v, audit/v1 defines %v", got, want)
	}
	for name, e := range events {
		members, row := rows[name][0], rows[name][1]
		var named []string
		for _, m := range backticked.FindAllStringSubmatch(members, -1) {
			named = append(named, m[1])
		}
		if got, want := slices.Sorted(slices.Values(named)), slices.Sorted(slices.Values(e.members)); !slices.Equal(got, want) {
			t.Errorf("%s: Section 12 names the members %v, audit/v1 allows %v", name, got, want)
		}
		for member, values := range e.values {
			for _, v := range values {
				if !strings.Contains(row, "`"+v+"`") {
					t.Errorf("%s: Section 12 does not say when %s is `%s`", name, member, v)
				}
			}
		}
	}
}
