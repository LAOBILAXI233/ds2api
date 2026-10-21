package toolcall

// The JSON tool-call block
//
// Besides the XML/EPSE/DSML forms, models routinely answer with a JSON call in
// a `<tool_call>` element — the shape Magpie's own protocol teaches:
//
//	<tool_call>{"name":"read_file","arguments":{"path":"README.md"}}</tool_call>
//
// Which is unambiguous: a complete element whose body parses as JSON and names
// a function is a call, never prose. The legacy `<tool_call><tool_name>…` XML
// dialect is NOT that shape and is still released as text: only a body that
// starts with `{` (or `[`) is considered here.

import (
	"encoding/json"
	"strings"
)

const (
	JSONToolCallOpen  = "<tool_call>"
	JSONToolCallClose = "</tool_call>"
)

// jsonToolCallFence unwraps a body the model wrapped in a Markdown fence.
func jsonToolCallFence(body string) string {
	trimmed := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmed, "```") {
		return trimmed
	}
	trimmed = strings.TrimPrefix(trimmed, "```")
	if newline := strings.IndexByte(trimmed, '\n'); newline >= 0 {
		trimmed = trimmed[newline+1:]
	} else {
		trimmed = ""
	}
	trimmed = strings.TrimSpace(trimmed)
	trimmed = strings.TrimSuffix(trimmed, "```")
	return strings.TrimSpace(trimmed)
}

// ParseJSONToolCallBody turns one JSON value into calls. Both a single
// {"name":…,"arguments":…} object and an array of them are accepted; the
// argument container may be spelled arguments / parameters / input.
func ParseJSONToolCallBody(body string) []ParsedToolCall {
	text := jsonToolCallFence(body)
	if text == "" {
		return nil
	}
	if strings.HasPrefix(text, "[") {
		var items []json.RawMessage
		if err := json.Unmarshal([]byte(text), &items); err != nil {
			return nil
		}
		calls := make([]ParsedToolCall, 0, len(items))
		for _, item := range items {
			if call, ok := parseJSONToolCallObject(item); ok {
				calls = append(calls, call)
			}
		}
		return calls
	}
	if call, ok := parseJSONToolCallObject([]byte(text)); ok {
		return []ParsedToolCall{call}
	}
	return nil
}

func parseJSONToolCallObject(raw []byte) (ParsedToolCall, bool) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ParsedToolCall{}, false
	}
	name := strings.TrimSpace(asStringValue(payload["name"]))
	if name == "" {
		if fn, ok := payload["function"].(map[string]any); ok {
			name = strings.TrimSpace(asStringValue(fn["name"]))
		}
	}
	if name == "" {
		return ParsedToolCall{}, false
	}
	var args any
	for _, key := range []string{"arguments", "parameters", "input"} {
		if value, ok := payload[key]; ok {
			args = value
			break
		}
	}
	input := map[string]any{}
	switch v := args.(type) {
	case map[string]any:
		input = v
	case string:
		if parsed := parseJSONObjectLoose(v); parsed != nil {
			input = parsed
		}
	}
	return ParsedToolCall{Name: name, Input: input}, true
}

func parseJSONObjectLoose(raw string) map[string]any {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil
	}
	return parsed
}

// ParseJSONToolCallBlocks collects the complete `<tool_call>{…}</tool_call>`
// elements in text. Blocks whose body is not JSON are left as text.
func ParseJSONToolCallBlocks(text string) []ParsedToolCall {
	if !strings.Contains(text, JSONToolCallOpen) {
		return nil
	}
	var calls []ParsedToolCall
	pos := 0
	for {
		open := strings.Index(strings.ToLower(text[pos:]), JSONToolCallOpen)
		if open < 0 {
			break
		}
		start := pos + open + len(JSONToolCallOpen)
		close := strings.Index(strings.ToLower(text[start:]), JSONToolCallClose)
		if close < 0 {
			break
		}
		calls = append(calls, ParseJSONToolCallBody(text[start:start+close])...)
		pos = start + close + len(JSONToolCallClose)
	}
	return calls
}

// FindJSONToolCallStart returns the index of a `<tool_call>` element whose body
// opens a JSON value. A mention in prose (`<tool_call>` followed by a newline or
// words) is not a start, so text still streams without being held back.
func FindJSONToolCallStart(text string, from int) (int, bool) {
	if from < 0 {
		from = 0
	}
	lower := strings.ToLower(text)
	for pos := from; pos < len(lower); {
		open := strings.Index(lower[pos:], JSONToolCallOpen)
		if open < 0 {
			return -1, false
		}
		start := pos + open
		body := start + len(JSONToolCallOpen)
		rest := strings.TrimLeft(text[body:], " \t\r\n")
		if strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, "[") {
			return start, true
		}
		pos = body
	}
	return -1, false
}

// IsPartialJSONToolCallPrefix reports whether a tail could still grow into
// `<tool_call>`: the sieve holds such a tail instead of streaming half a marker.
func IsPartialJSONToolCallPrefix(text string) bool {
	if text == "" || !strings.HasPrefix(text, "<") {
		return false
	}
	lower := strings.ToLower(text)
	// A complete marker is not partial; only a proper prefix of it is.
	if len(lower) >= len(JSONToolCallOpen) {
		return false
	}
	return strings.HasPrefix(JSONToolCallOpen, lower)
}
