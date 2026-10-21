'use strict';

// JSON tool-call capture for the streaming sieve (Node/Vercel runtime).
// Mirrors internal/toolstream/tool_sieve_jsoncall.go: hold from
// `<tool_call>` (only when a JSON value follows) until its closing tag, then
// hand the parsed call over; release as text when it is not a call.

const {
  findJSONToolCallStart,
  parseJSONToolCallBody,
  JSON_TOOL_CALL_OPEN,
  JSON_TOOL_CALL_CLOSE,
} = require('./parse_payload');

const JSON_TOOL_CALL_RUNAWAY = 128 * 1024;

function consumeJSONToolCapture(captured) {
  const text = typeof captured === 'string' ? captured : '';
  if (!text) {
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const start = findJSONToolCallStart(text, 0);
  if (!start.ok) {
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const prefix = text.slice(0, start.start);
  const bodyStart = start.start + JSON_TOOL_CALL_OPEN.length;
  const closeIdx = text.toLowerCase().indexOf(JSON_TOOL_CALL_CLOSE, bodyStart);
  if (closeIdx < 0) {
    if (text.length > JSON_TOOL_CALL_RUNAWAY) {
      return { ready: true, prefix: text, calls: [], suffix: '' };
    }
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const suffix = text.slice(closeIdx + JSON_TOOL_CALL_CLOSE.length);
  const calls = parseJSONToolCallBody(text.slice(bodyStart, closeIdx));
  if (!calls.length) {
    return { ready: true, prefix: text, calls: [], suffix: '' };
  }
  return { ready: true, prefix, calls, suffix };
}

function hasOpenJSONToolCall(captured) {
  const text = typeof captured === 'string' ? captured : '';
  const start = findJSONToolCallStart(text, 0);
  if (!start.ok) {
    return false;
  }
  const bodyStart = start.start + JSON_TOOL_CALL_OPEN.length;
  if (bodyStart >= text.length) {
    return true;
  }
  if (text.toLowerCase().indexOf(JSON_TOOL_CALL_CLOSE, bodyStart) >= 0) {
    return false;
  }
  return text.length <= JSON_TOOL_CALL_RUNAWAY;
}

module.exports = {
  consumeJSONToolCapture,
  hasOpenJSONToolCall,
  JSON_TOOL_CALL_OPEN,
  JSON_TOOL_CALL_RUNAWAY,
};
