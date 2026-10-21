package toolstream

import (
	"strings"
	"testing"
)

func collectEvents(t *testing.T, chunks []string, toolNames []string) (text string, calls int, events []Event) {
	t.Helper()
	var state State
	var all []Event
	for _, chunk := range chunks {
		all = append(all, ProcessChunk(&state, chunk, toolNames)...)
	}
	all = append(all, Flush(&state, toolNames)...)
	var b strings.Builder
	for _, evt := range all {
		b.WriteString(evt.Content)
		calls += len(evt.ToolCalls)
	}
	return b.String(), calls, all
}

// The web client's DSML wrapper, split across deltas the way a stream delivers
// it. The block must parse into one call and leave no markup in the reply.
func TestSieveDSMLWrapperSplitAcrossChunks(t *testing.T) {
	chunks := []string{
		"结果如下：\n<｜｜DSML｜｜ calls>\n<｜｜DSML｜｜ invoke name=",
		`"exec_command">`,
		"\n<｜｜DSML｜｜ parameter name=\"cmd\" string=\"true\">ls -la",
		"</｜｜DSML｜｜ parameter>\n</｜｜DSML｜｜ invoke>\n</｜｜DSML｜｜ calls>",
		" 完成",
	}
	text, calls, events := collectEvents(t, chunks, []string{"exec_command"})
	if calls != 1 {
		t.Fatalf("expected one tool call, got %d events=%#v", calls, events)
	}
	if strings.Contains(text, "DSML") || strings.Contains(text, "invoke") || strings.Contains(text, "parameter") {
		t.Fatalf("DSML markup leaked into text: %q", text)
	}
	if !strings.Contains(text, "结果如下") || !strings.Contains(text, "完成") {
		t.Fatalf("surrounding text was lost: %q", text)
	}
}

// A DSML block that arrives without the `<tool_calls>` wrapper.
func TestSieveDSMLBareInvokeSplitAcrossChunks(t *testing.T) {
	chunks := []string{
		"<｜｜DSML｜｜ invoke name=\"read_file\">",
		`<｜｜DSML｜｜ parameter name="path">README.md</｜｜DSML｜｜ parameter>`,
		"</｜｜DSML｜｜ invoke>",
	}
	text, calls, events := collectEvents(t, chunks, nil)
	if calls != 1 {
		t.Fatalf("expected one tool call, got %d events=%#v", calls, events)
	}
	if strings.Contains(text, "DSML") || strings.Contains(text, "read_file") {
		t.Fatalf("bare DSML leaked into text: %q", text)
	}
}

// The JSON block form, split so the marker itself spans two deltas.
func TestSieveJSONToolCallSplitAcrossChunks(t *testing.T) {
	chunks := []string{
		"先看一下文件。\n<tool_ca",
		`ll>{"name":"read_file","arguments":{"path":`,
		`"README.md"}}</tool_call>`,
		"\n然后继续。",
	}
	text, calls, events := collectEvents(t, chunks, []string{"read_file"})
	if calls != 1 {
		t.Fatalf("expected one tool call, got %d events=%#v", calls, events)
	}
	if strings.Contains(text, "<tool_call>") || strings.Contains(text, "read_file") {
		t.Fatalf("JSON tool call leaked into text: %q", text)
	}
	if !strings.Contains(text, "先看一下文件") || !strings.Contains(text, "然后继续") {
		t.Fatalf("surrounding text was lost: %q", text)
	}
}

// A prose mention of the marker must keep streaming: no JSON body follows, so
// the sieve neither holds nor treats it as a call.
func TestSieveJSONMarkerMentionStreamsAsText(t *testing.T) {
	var state State
	events := ProcessChunk(&state, "格式是 <tool_call> 后面接 JSON。\n", nil)
	events = append(events, Flush(&state, nil)...)
	var b strings.Builder
	for _, evt := range events {
		b.WriteString(evt.Content)
		if len(evt.ToolCalls) > 0 {
			t.Fatalf("a prose mention became a tool call: %#v", evt.ToolCalls)
		}
	}
	if !strings.Contains(b.String(), "<tool_call>") {
		t.Fatalf("expected the mention to stream as text, got %q", b.String())
	}
}

// A complete JSON block whose body is not a call is released as text rather
// than swallowed.
func TestSieveJSONToolCallWithUnparseableBodyIsReleased(t *testing.T) {
	var state State
	events := ProcessChunk(&state, `<tool_call>{"note":"not a call"}</tool_call>`, nil)
	events = append(events, Flush(&state, nil)...)
	var b strings.Builder
	calls := 0
	for _, evt := range events {
		b.WriteString(evt.Content)
		calls += len(evt.ToolCalls)
	}
	if calls != 0 {
		t.Fatalf("expected no calls, got %d", calls)
	}
	if !strings.Contains(b.String(), "not a call") {
		t.Fatalf("expected the block to be released as text, got %q", b.String())
	}
}
