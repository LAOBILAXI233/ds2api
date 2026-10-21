package toolcall

import (
	"strings"
	"testing"
)

// The exact shape the web client's models emit: the DSML shell around a
// "calls" wrapper, an invoke per call and a parameter per argument.
func TestParseDSMLWrapperBlock(t *testing.T) {
	text := strings.Join([]string{
		"<｜｜DSML｜｜ calls>",
		`<｜｜DSML｜｜ invoke name="exec_command">`,
		`<｜｜DSML｜｜ parameter name="cmd" string="true">ls -la /tmp</｜｜DSML｜｜ parameter>`,
		"</｜｜DSML｜｜ invoke>",
		"</｜｜DSML｜｜ calls>",
	}, "\n")

	calls := ParseToolCalls(text, []string{"exec_command"})
	if len(calls) != 1 {
		t.Fatalf("expected one DSML call, got %#v", calls)
	}
	if calls[0].Name != "exec_command" {
		t.Fatalf("unexpected tool name: %#v", calls[0])
	}
	if got := calls[0].Input["cmd"]; got != "ls -la /tmp" {
		t.Fatalf("unexpected cmd argument: %#v", calls[0].Input)
	}
}

func TestParseDSMLWrapperBlockWithTwoInvokes(t *testing.T) {
	text := strings.Join([]string{
		"<｜｜DSML｜｜ calls>",
		`<｜｜DSML｜｜ invoke name="read_file">`,
		`<｜｜DSML｜｜ parameter name="path">main.go</｜｜DSML｜｜ parameter>`,
		"</｜｜DSML｜｜ invoke>",
		`<｜｜DSML｜｜ invoke name="Bash">`,
		`<｜｜DSML｜｜ parameter name="command">pwd</｜｜DSML｜｜ parameter>`,
		"</｜｜DSML｜｜ invoke>",
		"</｜｜DSML｜｜ calls>",
	}, "\n")

	calls := ParseToolCalls(text, nil)
	if len(calls) != 2 {
		t.Fatalf("expected two DSML calls, got %#v", calls)
	}
	if calls[0].Name != "read_file" || calls[1].Name != "Bash" {
		t.Fatalf("unexpected calls: %#v", calls)
	}
	if calls[0].Input["path"] != "main.go" || calls[1].Input["command"] != "pwd" {
		t.Fatalf("unexpected arguments: %#v", calls)
	}
}

// Models often drop the wrapper entirely; a complete invoke block is still a
// call, and magpie parses it the same way.
func TestParseDSMLBareInvokeBlockWithoutWrapper(t *testing.T) {
	text := strings.Join([]string{
		`<｜｜DSML｜｜ invoke name="exec_command">`,
		`<｜｜DSML｜｜ parameter name="cmd" string="true">git status</｜｜DSML｜｜ parameter>`,
		"</｜｜DSML｜｜ invoke>",
	}, "\n")

	calls := ParseToolCalls(text, nil)
	if len(calls) != 1 {
		t.Fatalf("expected one bare DSML call, got %#v", calls)
	}
	if calls[0].Name != "exec_command" || calls[0].Input["cmd"] != "git status" {
		t.Fatalf("unexpected call: %#v", calls[0])
	}
}

// A `calls` wrapper is only a tool wrapper when the shell says DSML, so the
// long-standing rule that `<tool-calls>` is a lookalike still holds.
func TestParseToolCallsStillIgnoresHyphenatedLookalike(t *testing.T) {
	text := `<tool-calls><invoke name="Bash"><parameter name="command">pwd</parameter></invoke></tool-calls>`
	if calls := ParseToolCalls(text, []string{"Bash"}); len(calls) != 0 {
		t.Fatalf("expected the hyphenated lookalike to stay text, got %#v", calls)
	}
}

func TestParseToolCallsStillIgnoresBareCallsTag(t *testing.T) {
	text := `<calls><invoke name="Bash"><parameter name="command">pwd</parameter></invoke></calls>`
	if calls := ParseToolCalls(text, []string{"Bash"}); len(calls) != 0 {
		t.Fatalf("expected a bare calls tag to stay text, got %#v", calls)
	}
}

func TestContainsDSMLMarker(t *testing.T) {
	cases := map[string]bool{
		"<｜｜DSML｜｜ calls>":             true,
		"<|DSML|calls>":                true,
		"<dsml calls>":                 true,
		"plain text about DSML format": false,
		"<tools><tool_call>":           false,
	}
	for text, want := range cases {
		if got := ContainsDSMLMarker(text); got != want {
			t.Fatalf("ContainsDSMLMarker(%q)=%v want %v", text, got, want)
		}
	}
}

func TestParseJSONToolCallBlock(t *testing.T) {
	text := `<tool_call>{"name":"read_file","arguments":{"path":"README.md"}}</tool_call>`
	calls := ParseToolCalls(text, nil)
	if len(calls) != 1 {
		t.Fatalf("expected one JSON tool call, got %#v", calls)
	}
	if calls[0].Name != "read_file" || calls[0].Input["path"] != "README.md" {
		t.Fatalf("unexpected call: %#v", calls[0])
	}
}

func TestParseJSONToolCallBlockArray(t *testing.T) {
	text := "<tool_call>[\n" +
		`{"name":"a","arguments":{"x":1}},` + "\n" +
		`{"name":"b","parameters":{"y":"z"}}` + "\n" +
		"]</tool_call>"
	calls := ParseToolCalls(text, nil)
	if len(calls) != 2 {
		t.Fatalf("expected two JSON tool calls, got %#v", calls)
	}
	if calls[0].Name != "a" || calls[1].Name != "b" {
		t.Fatalf("unexpected calls: %#v", calls)
	}
	if calls[1].Input["y"] != "z" {
		t.Fatalf("unexpected parameters: %#v", calls[1].Input)
	}
}

// A `<tool_call>` that does not carry JSON (the legacy XML dialect) stays text.
func TestParseLegacyXMLToolCallStaysText(t *testing.T) {
	text := `<tool_call><tool_name>read_file</tool_name><param>{"path":"a"}</param></tool_call>`
	if calls := ParseToolCalls(text, nil); len(calls) != 0 {
		t.Fatalf("expected legacy XML tool_call to stay text, got %#v", calls)
	}
}

func TestFindJSONToolCallStartRequiresJSONBody(t *testing.T) {
	if _, ok := FindJSONToolCallStart("prefix <tool_call>\n", 0); ok {
		t.Fatal("a mention without a JSON body must not start a capture")
	}
	if start, ok := FindJSONToolCallStart(`prefix <tool_call>{"name":"a"}`, 0); !ok || start != 7 {
		t.Fatalf("expected start=7, got start=%d ok=%v", start, ok)
	}
}

func TestIsPartialJSONToolCallPrefix(t *testing.T) {
	if !IsPartialJSONToolCallPrefix("<tool_ca") {
		t.Fatal("expected a partial marker to be held")
	}
	if IsPartialJSONToolCallPrefix("<tool_call>") {
		t.Fatal("a complete marker is not partial")
	}
	if IsPartialJSONToolCallPrefix("<p") {
		t.Fatal("an unrelated tag is not a tool marker")
	}
}
