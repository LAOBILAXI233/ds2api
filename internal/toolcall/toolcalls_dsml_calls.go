package toolcall

// The web client's own agent markup
//
// The chat.deepseek.com models write tool calls in DeepSeek's internal DSML
// format whenever the conversation looks agent-like, whether or not a prompt
// protocol was agreed on:
//
//	<｜｜DSML｜｜ calls>
//	<｜｜DSML｜｜ invoke name="exec_command">
//	<｜｜DSML｜｜ parameter name="cmd" string="true">ls -la</｜｜DSML｜｜ parameter>
//	</｜｜DSML｜｜ invoke>
//	</｜｜DSML｜｜ calls>
//
// The scanner already canonicalises the tags (the shell is "arbitrary prefix +
// separator + local name", which is what the <|EPSE|…> form is too), so DSML
// invoke/parameter blocks parse as soon as the "calls" wrapper alias exists.
// What is not covered by that is a block that arrives WITHOUT the wrapper:
// `parseXMLToolCalls` needs a `<tool_calls>` element, so a bare DSML invoke
// block was released as visible text. This file adds the wrapper-less path and
// the marker test that keeps it scoped to DSML output.

import "strings"

// ContainsDSMLMarker reports whether text carries the web client's DSML tag
// shell anywhere (any of the pipe/fullwidth spellings, uppercase or not).
func ContainsDSMLMarker(text string) bool {
	if text == "" {
		return false
	}
	lower := normalizedASCIILowerString(text)
	if !strings.Contains(lower, "dsml") {
		return false
	}
	// Require the shell around it, not just the word in prose: a tag opener,
	// optional separators, then "dsml".
	for i := 0; i < len(lower); {
		next, ok := consumeToolMarkupLessThan(text, i)
		if !ok {
			i++
			continue
		}
		idx := next
		idx, _ = consumeToolMarkupNamePrefix(text, idx)
		if idx == next {
			// No separator shell: the word may still be the first prefix
			// segment (`<DSML calls>`), which the alias path handles.
			idx = next
		}
		if strings.HasPrefix(normalizedASCIILowerString(text[idx:]), "dsml") {
			return true
		}
		i = next
	}
	return false
}

// ParseCompleteInvokeBlocks parses the `<invoke>` blocks of a wrapper-less tool
// block and reports whether the whole text is accounted for: everything after
// the last closing invoke tag must be whitespace or a closing wrapper, never
// prose. That is the condition under which the streaming sieve can treat the
// captured text as finished instead of waiting for a wrapper that will never
// arrive.
func ParseCompleteInvokeBlocks(text string) ([]ParsedToolCall, bool) {
	if strings.TrimSpace(text) == "" {
		return nil, false
	}
	normalized, _ := normalizeEPSEToolCallMarkup(text)
	invokes := findXMLElementBlocks(normalized, "invoke")
	if len(invokes) == 0 {
		return nil, false
	}
	calls := make([]ParsedToolCall, 0, len(invokes))
	for _, block := range invokes {
		call, ok := parseSingleXMLToolCall(block)
		if !ok {
			return nil, false
		}
		calls = append(calls, call)
	}
	tail := strings.TrimSpace(normalized[invokes[len(invokes)-1].End:])
	if tail != "" && !isClosingWrapperOnly(tail) {
		return nil, false
	}
	return calls, true
}

// isClosingWrapperOnly reports whether text is nothing but one or more closing
// tool_calls wrapper tags, optionally preceded by a closing prefix (`</｜｜DSML｜｜ calls>`).
func isClosingWrapperOnly(text string) bool {
	remaining := strings.TrimSpace(text)
	for remaining != "" {
		tag, ok := FindToolMarkupTagOutsideIgnored(remaining, 0)
		if !ok || !tag.Closing || tag.Start != 0 {
			return false
		}
		remaining = strings.TrimSpace(remaining[tag.End+1:])
	}
	return true
}

// ParseDSMLToolCalls parses a DSML block that carries no `<tool_calls>` wrapper.
// It returns nothing unless the text really is DSML markup, so ordinary prose
// that happens to contain an `<invoke>` example is untouched.
func ParseDSMLToolCalls(text string, _ []string) []ParsedToolCall {
	if !ContainsDSMLMarker(text) {
		return nil
	}
	calls, ok := ParseCompleteInvokeBlocks(text)
	if !ok {
		return nil
	}
	return calls
}
