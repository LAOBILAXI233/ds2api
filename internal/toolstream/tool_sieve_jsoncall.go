package toolstream

// JSON tool-call capture for the streaming sieve.
//
// `<tool_call>{"name":"x","arguments":{…}}</tool_call>` is captured as a block:
// the sieve holds from the opening marker (only when a JSON value follows it, so
// a mention in prose streams straight through) until the closing tag arrives,
// then hands the parsed call to the caller. A block that never closes, or whose
// body is not JSON, is released as text instead of being swallowed.

import (
	"strings"

	"ds2api/internal/toolcall"
)

// jsonToolCallRunaway bounds a block that never closes. Beyond it the block was
// meant as markup, not reply, but it is still better released as text than held
// for the rest of the stream.
const jsonToolCallRunaway = 128 * 1024

// consumeJSONToolCapture parses a captured JSON tool-call block.
//
// ready=false means "keep buffering"; ready=true with no calls means "this was
// not a call, let it flow as text".
func consumeJSONToolCapture(captured string, _ []string) (prefix string, calls []toolcall.ParsedToolCall, suffix string, ready bool) {
	if captured == "" {
		return "", nil, "", false
	}
	start, ok := toolcall.FindJSONToolCallStart(captured, 0)
	if !ok {
		return "", nil, "", false
	}
	prefix = captured[:start]
	bodyStart := start + len(toolcall.JSONToolCallOpen)
	closeIdx := strings.Index(strings.ToLower(captured[bodyStart:]), toolcall.JSONToolCallClose)
	if closeIdx < 0 {
		if len(captured) > jsonToolCallRunaway {
			return captured, nil, "", true
		}
		return "", nil, "", false
	}
	body := captured[bodyStart : bodyStart+closeIdx]
	suffix = captured[bodyStart+closeIdx+len(toolcall.JSONToolCallClose):]
	parsed := toolcall.ParseJSONToolCallBody(body)
	if len(parsed) == 0 {
		// Complete but not a JSON call: it was prose after all.
		return captured, nil, "", true
	}
	return prefix, parsed, suffix, true
}

// findJSONToolSegmentStart is findToolSegmentStart's counterpart for the JSON
// form: it skips a marker inside a code fence or an inline code span, exactly as
// the XML side does.
func findJSONToolSegmentStart(state *State, s string) int {
	if s == "" {
		return -1
	}
	offset := 0
	for {
		start, ok := toolcall.FindJSONToolCallStart(s, offset)
		if !ok {
			return -1
		}
		if insideCodeFenceWithState(state, s[:start]) {
			offset = start + len(toolcall.JSONToolCallOpen)
			continue
		}
		markdown := markdownCodeSpanStateAt(state, s[:start])
		if markdown.ticks == 0 {
			return includeDuplicateLeadingLessThan(s, start)
		}
		if markdownCodeSpanCloses(s[start:], markdown.ticks) {
			offset = start + len(toolcall.JSONToolCallOpen)
			continue
		}
		if markdown.fromPrior {
			return holdToolSegmentStart
		}
		return includeDuplicateLeadingLessThan(s, start)
	}
}
