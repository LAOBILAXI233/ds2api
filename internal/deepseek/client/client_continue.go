package client

import (
	"bufio"
	"bytes"
	"context"
	dsprotocol "ds2api/internal/deepseek/protocol"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"ds2api/internal/auth"
	"ds2api/internal/config"
)

const defaultAutoContinueLimit = 8

type continueOpenFunc func(context.Context, string, int) (*http.Response, error)

type continueState struct {
	sessionID         string
	responseMessageID int
	lastStatus        string
	// finalStatus is the reply's own `response/status` (never quasi_status):
	// only a real FINISHED without content is the empty answer the page
	// re-reads through /chat/resume_stream.
	finalStatus string
	finished    bool
	// hasContent records that the stream carried actual reply material (text or
	// thinking). A FINISHED stream without any is the "empty answer" the page
	// itself repairs by re-reading the message through /chat/resume_stream.
	hasContent bool
	// sawDone records that some round carried the [DONE] sentinel; the spliced
	// stream forwards exactly one at the very end.
	sawDone bool
	// canResume marks that a resume endpoint is wired up, which is what makes
	// withholding the final status line meaningful.
	canResume bool
	// resumed records that the empty reply has already been re-read.
	resumed bool
	// heldFinalStatus keeps the `response/status: FINISHED` frame that ended an
	// empty reply. It is released only once no resume will follow: both
	// consumers stop reading at that frame, so forwarding it early would make
	// the resumed stream unreadable.
	heldFinalStatus []string
}

// wrapCompletionWithAutoContinue wraps the completion response body so that
// if the upstream indicates the response is incomplete (INCOMPLETE /
// AUTO_CONTINUE), ds2api will automatically call the DeepSeek continue
// endpoint and splice the continuation SSE stream onto the original.
// An empty-but-FINISHED reply is re-read through /chat/resume_stream once, the
// way the web client repairs it.
// The caller sees a single, seamless SSE stream.
func (c *Client) wrapCompletionWithAutoContinue(ctx context.Context, a *auth.RequestAuth, payload map[string]any, powResp string, resp *http.Response) *http.Response {
	if resp == nil || resp.Body == nil {
		return resp
	}
	sessionID, _ := payload["chat_session_id"].(string)
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return resp
	}
	config.Logger.Debug("[auto_continue] wrapping completion response", "session_id", sessionID)
	resp.Body = newAutoContinueBody(ctx, resp.Body, sessionID, defaultAutoContinueLimit, func(ctx context.Context, sessionID string, responseMessageID int) (*http.Response, error) {
		return c.callContinue(ctx, a, sessionID, responseMessageID, powResp)
	}, func(ctx context.Context, sessionID string, responseMessageID int) (*http.Response, error) {
		return c.callResumeStream(ctx, a, sessionID, responseMessageID)
	})
	return resp
}

// callContinue sends a continue request to DeepSeek to resume generation.
//
// Only /api/v0/chat/completion takes a proof of work: the challenge names its
// target_path, and DeepSeek answers INVALID_TARGET_PATH to a challenge solved
// for another path. /chat/continue and /chat/resume_stream are therefore sent
// with no x-ds-pow-response at all (measured against the web client), which is
// why powResp is accepted but never forwarded.
func (c *Client) callContinue(ctx context.Context, a *auth.RequestAuth, sessionID string, responseMessageID int, powResp string) (*http.Response, error) {
	if strings.TrimSpace(sessionID) == "" || responseMessageID <= 0 {
		return nil, errors.New("missing continue identifiers")
	}
	_ = powResp
	return c.postChatContinuation(ctx, a, dsprotocol.DeepSeekContinueURL, "continue", map[string]any{
		"chat_session_id":    sessionID,
		"message_id":         responseMessageID,
		"fallback_to_resume": true,
	})
}

// callResumeStream re-opens a finished message so the page's own stream can be
// read again. It is what DeepSeek's web client calls when a reply ends without
// any visible content; like /chat/continue it takes no proof of work.
func (c *Client) callResumeStream(ctx context.Context, a *auth.RequestAuth, sessionID string, responseMessageID int) (*http.Response, error) {
	if strings.TrimSpace(sessionID) == "" || responseMessageID <= 0 {
		return nil, errors.New("missing resume identifiers")
	}
	return c.postChatContinuation(ctx, a, dsprotocol.DeepSeekResumeStreamURL, "resume_stream", map[string]any{
		"chat_session_id": sessionID,
		"message_id":      responseMessageID,
	})
}

func (c *Client) postChatContinuation(ctx context.Context, a *auth.RequestAuth, url, op string, payload map[string]any) (*http.Response, error) {
	clients := c.requestClientsForAuth(ctx, a)
	headers := c.authHeadersForAuth(a)
	c.applyHIFHeaders(ctx, a, headers)
	applySessionReferer(headers, payload)
	config.Logger.Info("[auto_continue] calling "+op, "session_id", payload["chat_session_id"], "account", a.AccountID)
	captureSession := c.capture.Start("deepseek_"+op, url, a.AccountID, payload)
	resp, err := c.streamPost(ctx, clients.stream, url, headers, payload)
	if err != nil {
		return nil, err
	}
	if captureSession != nil {
		resp.Body = captureSession.WrapBody(resp.Body, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errors.New(op + " failed")
	}
	return resp, nil
}

type resumeOpenFunc func(context.Context, string, int) (*http.Response, error)

// newAutoContinueBody returns a new ReadCloser that transparently pumps
// continuation rounds via an io.Pipe.
func newAutoContinueBody(ctx context.Context, initial io.ReadCloser, sessionID string, maxRounds int, openContinue continueOpenFunc, openResume resumeOpenFunc) io.ReadCloser {
	if initial == nil || strings.TrimSpace(sessionID) == "" || openContinue == nil {
		return initial
	}
	if maxRounds <= 0 {
		maxRounds = defaultAutoContinueLimit
	}
	pr, pw := io.Pipe()
	state := continueState{sessionID: sessionID, canResume: openResume != nil}
	go pumpAutoContinue(ctx, pw, initial, state, maxRounds, openContinue, openResume)
	return pr
}

// pumpAutoContinue is the goroutine that drives the auto-continue loop.
// It reads the initial SSE body, checks whether a continue is required,
// and if so opens a new continue stream and splices it onto the pipe writer.
// An empty but FINISHED reply is re-read once through resume_stream first.
func pumpAutoContinue(ctx context.Context, pw *io.PipeWriter, initial io.ReadCloser, state continueState, maxRounds int, openContinue continueOpenFunc, openResume resumeOpenFunc) {
	defer func() { _ = pw.Close() }()
	current := initial
	rounds := 0
	for {
		_, err := streamBodyWithContinueState(ctx, pw, current, &state)
		_ = current.Close()
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if state.shouldContinue() && rounds < maxRounds {
			rounds++
			config.Logger.Info("[auto_continue] continuing", "round", rounds, "session_id", state.sessionID, "message_id", state.responseMessageID, "status", state.lastStatus)
			nextResp, err := openContinue(ctx, state.sessionID, state.responseMessageID)
			if err != nil {
				config.Logger.Warn("[auto_continue] continue request failed", "round", rounds, "error", err)
				_ = pw.CloseWithError(err)
				return
			}
			current = nextResp.Body
			state.prepareForNextRound()
			continue
		}
		if state.shouldResume(state.resumed) && openResume != nil {
			// The resumed round brings its own FINISHED frame, so the withheld
			// one is dropped — but only once the resume is actually open: if it
			// fails, that frame is the only way the consumer learns the turn
			// ended.
			held := state.heldFinalStatus
			state.heldFinalStatus = nil
			state.resumed = true
			config.Logger.Info("[auto_continue] empty finished reply, re-reading through resume_stream", "session_id", state.sessionID, "message_id", state.responseMessageID)
			nextResp, err := openResume(ctx, state.sessionID, state.responseMessageID)
			if err != nil {
				// The reply really was empty: leave the turn to the normal
				// empty-output retry instead of failing the request.
				config.Logger.Warn("[auto_continue] resume_stream failed", "error", err)
				state.heldFinalStatus = held
				break
			}
			current = nextResp.Body
			state.prepareForNextRound()
			continue
		}
		break
	}
	// The withheld FINISHED frame goes out now that no resume will follow. It
	// has to be released before [DONE] because both consumers stop at it.
	if err := flushHeldFinalStatus(pw, &state); err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	// Emit the final [DONE] sentinel only when the upstream had one; a stream
	// that ended without it is closed as it came.
	if state.sawDone {
		if _, err := io.Copy(pw, bytes.NewBufferString("data: [DONE]\n")); err != nil {
			_ = pw.CloseWithError(err)
		}
	}
}

// streamBodyWithContinueState scans an SSE body line-by-line, writing each
// line through to pw while observing state signals. Intermediate [DONE]
// sentinels are consumed (not forwarded) so that the downstream only sees
// one final [DONE] at the very end.
func streamBodyWithContinueState(ctx context.Context, pw *io.PipeWriter, body io.Reader, state *continueState) (bool, error) {
	reader := bufio.NewReaderSize(body, 64*1024)
	hadDone := false
	for {
		select {
		case <-ctx.Done():
			return hadDone, ctx.Err()
		default:
		}
		line, err := reader.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			if err == io.EOF {
				return hadDone, nil
			}
			return hadDone, err
		}
		trimmed := strings.TrimSpace(string(line))
		if trimmed != "" {
			if strings.HasPrefix(trimmed, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				if data == "[DONE]" {
					hadDone = true
					state.observeDone()
					if err != nil && err != io.EOF {
						return hadDone, err
					}
					if err == io.EOF {
						return hadDone, nil
					}
					continue
				}
				state.observe(data)
				if state.holdFinalStatusLine(data) {
					// Withheld: forwarding it here is what stops both the
					// stream and the non-stream consumer, and the resumed
					// round would then never be read. Keep it newline-
					// terminated so replaying it yields a well-formed frame.
					held := string(line)
					if !strings.HasSuffix(held, "\n") {
						held += "\n"
					}
					state.heldFinalStatus = append(state.heldFinalStatus, held)
					if err != nil && err != io.EOF {
						return hadDone, err
					}
					if err == io.EOF {
						return hadDone, nil
					}
					continue
				}
			}
			if !strings.HasSuffix(string(line), "\n") {
				line = append(line, '\n')
			}
			if _, copyErr := io.Copy(pw, bytes.NewReader(line)); copyErr != nil {
				return hadDone, copyErr
			}
		}
		if err != nil {
			if err == io.EOF {
				return hadDone, nil
			}
			return hadDone, err
		}
	}
}

// observeDone records a [DONE] sentinel. The spliced stream forwards exactly
// one at the end, whichever round it came from.
func (s *continueState) observeDone() {
	if s == nil {
		return
	}
	s.sawDone = true
}

// observe extracts continue-relevant signals from an SSE JSON chunk.
func (s *continueState) observe(data string) {
	if s == nil || strings.TrimSpace(data) == "" {
		return
	}
	var chunk map[string]any
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return
	}
	if s.hasReplyContent(chunk) {
		s.hasContent = true
	}
	// Top-level response_message_id
	if id := intFrom(chunk["response_message_id"]); id > 0 {
		s.responseMessageID = id
	}
	s.observeDirectPatch(asString(chunk["p"]), chunk["v"])
	if p, _ := chunk["p"].(string); p == "response" {
		s.observeBatchPatches("response", chunk["v"])
	} else {
		s.observeBatchPatches("", chunk["v"])
	}
	if v, _ := chunk["v"].(map[string]any); v != nil {
		s.observeResponseObject(v["response"])
	}
	if message, _ := chunk["message"].(map[string]any); message != nil {
		s.observeResponseObject(message["response"])
	}
}

// hasReplyContent reports whether one SSE frame carries reply material. A bare
// string value with no patch path ({"v":"UG"}) is an append to the fragment
// being written, so it counts; content/thinking_content fields and fragments
// with a non-empty content count as well. Everything else (status, ids,
// token counters) does not.
func (s *continueState) hasReplyContent(chunk map[string]any) bool {
	if chunk == nil {
		return false
	}
	p, _ := chunk["p"].(string)
	path := strings.TrimSpace(p)
	if path == "" {
		// A bare string value with no patch path is an append to the fragment
		// being written.
		if v, ok := chunk["v"].(string); ok && strings.TrimSpace(v) != "" {
			return true
		}
	}
	// A patch addressed at a content path carries reply material in `v`,
	// whatever its shape: {"p":"response/content","v":"hi"} or
	// {"p":"response/fragments/-1/content","o":"APPEND","v":"hi"}.
	if strings.Contains(strings.ToLower(path), "content") && hasNonEmptyTextValue(chunk["v"]) {
		return true
	}
	return frameHasContentValue(chunk, 0)
}

// hasNonEmptyTextValue reports whether a patch value carries visible text: a
// non-blank string, an object holding text/content, or a fragment list.
func hasNonEmptyTextValue(value any) bool {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case map[string]any:
		for _, key := range []string{"text", "content"} {
			if text, ok := v[key].(string); ok && strings.TrimSpace(text) != "" {
				return true
			}
		}
		return frameHasContentValue(v, 0)
	case []any:
		for _, item := range v {
			if hasNonEmptyTextValue(item) {
				return true
			}
		}
	}
	return false
}

func frameHasContentValue(value any, depth int) bool {
	if depth > 6 {
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		for key, inner := range v {
			switch key {
			case "content", "thinking_content", "reasoning_content":
				if text, ok := inner.(string); ok && strings.TrimSpace(text) != "" {
					return true
				}
			}
			if frameHasContentValue(inner, depth+1) {
				return true
			}
		}
	case []any:
		for _, inner := range v {
			if frameHasContentValue(inner, depth+1) {
				return true
			}
		}
	}
	return false
}

func (s *continueState) observeDirectPatch(path string, value any) {
	if s == nil {
		return
	}
	switch strings.Trim(strings.TrimSpace(path), "/") {
	case "response/status", "status":
		s.setStatus(asString(value))
		s.setFinalStatus(asString(value))
	case "response/quasi_status", "quasi_status":
		s.setStatus(asString(value))
	case "response/auto_continue", "auto_continue":
		if v, ok := value.(bool); ok && v {
			s.lastStatus = "AUTO_CONTINUE"
		}
	}
}

func (s *continueState) observeResponseObject(raw any) {
	if s == nil {
		return
	}
	response, _ := raw.(map[string]any)
	if response == nil {
		return
	}
	if id := intFrom(response["message_id"]); id > 0 {
		s.responseMessageID = id
	}
	s.setStatus(asString(response["status"]))
	s.setFinalStatus(asString(response["status"]))
	if autoContinue, ok := response["auto_continue"].(bool); ok && autoContinue {
		s.lastStatus = "AUTO_CONTINUE"
	}
}

func (s *continueState) observeBatchPatches(parentPath string, raw any) {
	if s == nil {
		return
	}
	patches, ok := raw.([]any)
	if !ok {
		return
	}
	for _, patch := range patches {
		m, ok := patch.(map[string]any)
		if !ok {
			continue
		}
		path := strings.TrimSpace(asString(m["p"]))
		if path == "" {
			continue
		}
		fullPath := path
		if parent := strings.Trim(strings.TrimSpace(parentPath), "/"); parent != "" && !strings.Contains(path, "/") {
			fullPath = parent + "/" + path
		}
		switch strings.Trim(strings.TrimSpace(fullPath), "/") {
		case "response/status", "status":
			s.setStatus(asString(m["v"]))
			s.setFinalStatus(asString(m["v"]))
		case "response/quasi_status", "quasi_status":
			s.setStatus(asString(m["v"]))
		case "response/auto_continue", "auto_continue":
			if v, ok := m["v"].(bool); ok && v {
				s.lastStatus = "AUTO_CONTINUE"
			}
		}
	}
}

func (s *continueState) setStatus(status string) {
	if s == nil {
		return
	}
	normalized := strings.TrimSpace(status)
	if normalized == "" {
		return
	}
	s.lastStatus = normalized
	if strings.EqualFold(normalized, "FINISHED") || strings.EqualFold(normalized, "CONTENT_FILTER") {
		s.finished = true
	}
}

// setFinalStatus records the reply's own status (never a quasi_status), which
// is what the resume decision is made on.
func (s *continueState) setFinalStatus(status string) {
	if s == nil {
		return
	}
	normalized := strings.ToUpper(strings.TrimSpace(status))
	if normalized == "" {
		return
	}
	s.finalStatus = normalized
}

// shouldContinue returns true when the upstream explicitly indicates the
// response is incomplete and we have enough information to issue a continue
// request. Plain WIP is not sufficient because normal streams begin in WIP.
func (s *continueState) shouldContinue() bool {
	if s == nil {
		return false
	}
	if s.finished || s.responseMessageID <= 0 || strings.TrimSpace(s.sessionID) == "" {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(s.lastStatus)) {
	case "INCOMPLETE", "AUTO_CONTINUE":
		return true
	default:
		return false
	}
}

// shouldResume returns true for a reply that FINISHED without carrying any text,
// thinking or tool call: the web client re-reads that message through
// /chat/resume_stream instead of accepting the empty answer.
func (s *continueState) shouldResume(alreadyResumed bool) bool {
	if s == nil || alreadyResumed {
		return false
	}
	if s.finalStatus != "FINISHED" {
		return false
	}
	if s.hasContent {
		return false
	}
	return s.responseMessageID > 0 && strings.TrimSpace(s.sessionID) != ""
}

// prepareForNextRound resets ephemeral state before processing the next
// continuation stream.
func (s *continueState) prepareForNextRound() {
	if s == nil {
		return
	}
	s.finished = false
	s.lastStatus = ""
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	default:
		s := strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(fmt.Sprint(v)), "\u0000", ""))
		if s == "<nil>" {
			return ""
		}
		return s
	}
}

// holdFinalStatusLine reports whether a frame is the `response/status: FINISHED`
// that ends a reply which has carried nothing. Such a frame is withheld until
// the resume decision is made, because consumers stop reading at it.
func (s *continueState) holdFinalStatusLine(data string) bool {
	if s == nil || !s.canResume || s.resumed || s.hasContent {
		return false
	}
	if !strings.Contains(strings.ToLower(data), "status") {
		return false
	}
	var chunk map[string]any
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return false
	}
	p, _ := chunk["p"].(string)
	switch strings.Trim(strings.TrimSpace(p), "/") {
	case "response/status", "status":
	default:
		return false
	}
	value, _ := chunk["v"].(string)
	return strings.EqualFold(strings.TrimSpace(value), "FINISHED")
}

// flushHeldFinalStatus releases the withheld FINISHED frame so the consumer can
// finalize the turn.
func flushHeldFinalStatus(pw *io.PipeWriter, state *continueState) error {
	if pw == nil || state == nil || len(state.heldFinalStatus) == 0 {
		return nil
	}
	held := state.heldFinalStatus
	state.heldFinalStatus = nil
	for _, line := range held {
		if _, err := io.Copy(pw, bytes.NewBufferString(line)); err != nil {
			return err
		}
	}
	return nil
}
