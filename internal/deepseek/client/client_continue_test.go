package client

import (
	"bytes"
	"context"
	dsprotocol "ds2api/internal/deepseek/protocol"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"ds2api/internal/auth"
)

type failingDoer struct {
	err error
}

func (d failingDoer) Do(_ *http.Request) (*http.Response, error) {
	return nil, d.err
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCallContinueSendsNoPowHeaderEvenOnFallbackTransport(t *testing.T) {
	var seenPow string
	var seenURL string

	client := &Client{
		stream: failingDoer{err: errors.New("stream transport failed")},
		fallbackS: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				seenPow = req.Header.Get("x-ds-pow-response")
				seenURL = req.URL.String()
				body := io.NopCloser(strings.NewReader("data: {\"p\":\"response/content\",\"v\":\"continued\"}\n" + "data: [DONE]\n"))
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       body,
					Request:    req,
				}, nil
			}),
		},
	}

	resp, err := client.callContinue(context.Background(), &auth.RequestAuth{
		DeepSeekToken: "token",
		AccountID:     "acct",
	}, "session-123", 99, "pow-response-abc")
	if err != nil {
		t.Fatalf("callContinue returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if seenPow != "" {
		t.Fatalf("continue must not carry a pow header, got %q", seenPow)
	}
	if seenURL != dsprotocol.DeepSeekContinueURL {
		t.Fatalf("continue request url=%q want=%q", seenURL, dsprotocol.DeepSeekContinueURL)
	}
}

func TestCallCompletionAutoContinueSendsNoPowHeader(t *testing.T) {
	var seenPow []string
	var seenURLs []string

	initialBody := strings.Join([]string{
		`data: {"response_message_id":321,"v":{"response":{"message_id":321,"status":"WIP","auto_continue":true}}}`,
		`data: [DONE]`,
	}, "\n") + "\n"

	client := &Client{
		stream: failingOrCompletionDoer{
			completionResp: &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(initialBody)),
			},
		},
		fallbackS: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				seenPow = append(seenPow, req.Header.Get("x-ds-pow-response"))
				seenURLs = append(seenURLs, req.URL.String())
				// The continued round finishes without any reply material, which
				// is exactly the empty answer resume_stream is for.
				body := io.NopCloser(strings.NewReader("data: {\"response_message_id\":322,\"v\":{\"response\":{\"message_id\":322,\"status\":\"FINISHED\"}}}\n" + "data: [DONE]\n"))
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       body,
					Request:    req,
				}, nil
			}),
		},
	}

	resp, err := client.CallCompletion(context.Background(), &auth.RequestAuth{
		DeepSeekToken: "token",
		AccountID:     "acct",
	}, map[string]any{
		"chat_session_id": "session-123",
	}, "pow-response-xyz", 1)
	if err != nil {
		t.Fatalf("CallCompletion returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read auto-continued body failed: %v", err)
	}
	for _, pow := range seenPow {
		if pow != "" {
			t.Fatalf("continuation requests must not carry a pow header, got %q", pow)
		}
	}
	wantURLs := []string{dsprotocol.DeepSeekContinueURL, dsprotocol.DeepSeekResumeStreamURL}
	if len(seenURLs) != len(wantURLs) {
		t.Fatalf("continuation urls=%v want=%v", seenURLs, wantURLs)
	}
	for i, want := range wantURLs {
		if seenURLs[i] != want {
			t.Fatalf("continuation url[%d]=%q want=%q", i, seenURLs[i], want)
		}
	}
	if !bytes.Contains(out, []byte(`"status":"WIP"`)) {
		t.Fatalf("expected initial stream content in body, got=%s", string(out))
	}
	if !bytes.Contains(out, []byte(`data: [DONE]`)) {
		t.Fatalf("expected final DONE sentinel in body, got=%s", string(out))
	}
}

func TestAutoContinueDoesNotTriggerOnPlainWIPWithoutExplicitContinuationSignal(t *testing.T) {
	initialBody := strings.Join([]string{
		`data: {"response_message_id":321,"v":{"response":{"message_id":321,"status":"WIP","auto_continue":false}}}`,
		`data: [DONE]`,
	}, "\n") + "\n"

	var continueCalls atomic.Int32
	body := newAutoContinueBody(context.Background(), io.NopCloser(strings.NewReader(initialBody)), "session-123", 8, func(context.Context, string, int) (*http.Response, error) {
		continueCalls.Add(1)
		return nil, errors.New("continue should not have been called")
	}, nil)
	defer func() { _ = body.Close() }()

	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if continueCalls.Load() != 0 {
		t.Fatalf("expected no continue calls, got %d", continueCalls.Load())
	}
	if !bytes.Contains(out, []byte(`"status":"WIP"`)) || !bytes.Contains(out, []byte(`data: [DONE]`)) {
		t.Fatalf("expected original body to pass through unchanged, got=%s", string(out))
	}
}

func TestAutoContinuePassesThroughLongSingleSSELine(t *testing.T) {
	payload := strings.Repeat("x", 2*1024*1024+4096)
	initialBody := `data: {"p":"response/content","v":"` + payload + `"}` + "\n" +
		`data: [DONE]` + "\n"

	body := newAutoContinueBody(context.Background(), io.NopCloser(strings.NewReader(initialBody)), "session-123", 8, func(context.Context, string, int) (*http.Response, error) {
		return nil, errors.New("continue should not have been called")
	}, nil)
	defer func() { _ = body.Close() }()

	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if !bytes.Contains(out, []byte(payload)) {
		t.Fatalf("expected long SSE payload to pass through, got len=%d want payload len=%d", len(out), len(payload))
	}
	if !bytes.Contains(out, []byte(`data: [DONE]`)) {
		t.Fatalf("expected final DONE sentinel in body, got len=%d", len(out))
	}
}

func TestAutoContinueTriggersOnDirectQuasiStatusIncomplete(t *testing.T) {
	initialBody := strings.Join([]string{
		`data: {"response_message_id":321,"p":"response/content","v":"<tool_calls><invoke name=\"write_file\"><parameter name=\"content\"><![CDATA[part-one"}`,
		`data: {"p":"response/quasi_status","v":"INCOMPLETE"}`,
		`data: [DONE]`,
	}, "\n") + "\n"

	var continueCalls atomic.Int32
	body := newAutoContinueBody(context.Background(), io.NopCloser(strings.NewReader(initialBody)), "session-123", 8, func(context.Context, string, int) (*http.Response, error) {
		continueCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`data: {"response_message_id":322,"p":"response/content","v":"-part-two]]></parameter></invoke></tool_calls>"}` + "\n" +
					`data: {"p":"response/status","v":"FINISHED"}` + "\n" +
					`data: [DONE]` + "\n",
			)),
		}, nil
	}, nil)
	defer func() { _ = body.Close() }()

	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if continueCalls.Load() != 1 {
		t.Fatalf("expected exactly one continue call, got %d", continueCalls.Load())
	}
	if !bytes.Contains(out, []byte("part-one")) || !bytes.Contains(out, []byte("-part-two")) {
		t.Fatalf("expected continued tool content in body, got=%s", string(out))
	}
}

func TestAutoContinueTriggersOnResponseBatchQuasiStatusIncomplete(t *testing.T) {
	initialBody := strings.Join([]string{
		`data: {"response_message_id":321,"v":{"response":{"message_id":321,"status":"WIP","auto_continue":false}}}`,
		`data: {"p":"response","o":"BATCH","v":[{"p":"accumulated_token_usage","v":2413},{"p":"quasi_status","v":"INCOMPLETE"}]}`,
		`data: [DONE]`,
	}, "\n") + "\n"

	var continueCalls atomic.Int32
	body := newAutoContinueBody(context.Background(), io.NopCloser(strings.NewReader(initialBody)), "session-123", 8, func(context.Context, string, int) (*http.Response, error) {
		continueCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`data: {"response_message_id":322,"p":"response/status","v":"FINISHED"}` + "\n" +
					`data: [DONE]` + "\n",
			)),
		}, nil
	}, nil)
	defer func() { _ = body.Close() }()

	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if continueCalls.Load() != 1 {
		t.Fatalf("expected exactly one continue call, got %d", continueCalls.Load())
	}
	if !bytes.Contains(out, []byte(`"quasi_status","v":"INCOMPLETE"`)) || !bytes.Contains(out, []byte(`"v":"FINISHED"`)) {
		t.Fatalf("expected continued output to include initial and final rounds, got=%s", string(out))
	}
}

func TestAutoContinueDoesNotTriggerWhenResponseBatchQuasiStatusFinished(t *testing.T) {
	initialBody := strings.Join([]string{
		`data: {"response_message_id":321,"v":{"response":{"message_id":321,"status":"WIP","auto_continue":false}}}`,
		`data: {"p":"response","o":"BATCH","v":[{"p":"accumulated_token_usage","v":2413},{"p":"quasi_status","v":"FINISHED"}]}`,
		`data: [DONE]`,
	}, "\n") + "\n"

	var continueCalls atomic.Int32
	body := newAutoContinueBody(context.Background(), io.NopCloser(strings.NewReader(initialBody)), "session-123", 8, func(context.Context, string, int) (*http.Response, error) {
		continueCalls.Add(1)
		return nil, errors.New("continue should not have been called")
	}, nil)
	defer func() { _ = body.Close() }()

	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if continueCalls.Load() != 0 {
		t.Fatalf("expected no continue calls, got %d", continueCalls.Load())
	}
	if !bytes.Contains(out, []byte(`"quasi_status","v":"FINISHED"`)) || !bytes.Contains(out, []byte(`data: [DONE]`)) {
		t.Fatalf("expected original finished body to pass through unchanged, got=%s", string(out))
	}
}

type failingOrCompletionDoer struct {
	completionResp *http.Response
}

func (d failingOrCompletionDoer) Do(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, "/chat/completion") {
		return d.completionResp, nil
	}
	return nil, errors.New("forced stream failure")
}

func TestAutoContinuePreservesIncompleteStateWhenNextChunkOmitsStatus(t *testing.T) {
	initialBody := strings.Join([]string{
		`data: {"response_message_id":321,"v":{"response":{"message_id":321,"status":"INCOMPLETE"}}}`,
		`data: {"p":"response/content","v":{"text":"continued"}}`,
		`data: [DONE]`,
	}, "\n") + "\n"

	var continueCalls atomic.Int32
	body := newAutoContinueBody(context.Background(), io.NopCloser(strings.NewReader(initialBody)), "session-123", 8, func(context.Context, string, int) (*http.Response, error) {
		continueCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`data: {"response_message_id":322,"p":"response/status","v":"FINISHED"}` + "\n" +
					`data: [DONE]` + "\n",
			)),
		}, nil
	}, nil)
	defer func() { _ = body.Close() }()

	_, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if continueCalls.Load() != 1 {
		t.Fatalf("expected exactly one continue call, got %d", continueCalls.Load())
	}
}

// A reply delivered only through path-addressed appends is NOT empty: the
// resume path must not re-read it (doing so would duplicate its text).
func TestShouldResumeIgnoresRepliesDeliveredByPathAppends(t *testing.T) {
	state := &continueState{sessionID: "session-123"}
	state.observe(`{"response_message_id":321,"p":"response/status","v":"FINISHED"}`)
	if !state.shouldResume(false) {
		t.Fatal("expected an empty finished reply to be resumable")
	}

	state = &continueState{sessionID: "session-123"}
	state.observe(`{"p":"response/fragments/-1/content","o":"APPEND","v":"hello"}`)
	state.observe(`{"response_message_id":321,"p":"response/status","v":"FINISHED"}`)
	if state.shouldResume(false) {
		t.Fatal("a reply with appended content must not be resumed")
	}

	state = &continueState{sessionID: "session-123"}
	state.observe(`{"p":"response/content","v":{"text":"hello"}}`)
	state.observe(`{"response_message_id":321,"p":"response/status","v":"FINISHED"}`)
	if state.shouldResume(false) {
		t.Fatal("a reply with object content must not be resumed")
	}

	state = &continueState{sessionID: "session-123"}
	state.observe(`{"p":"response/thinking_content","v":"pondering"}`)
	state.observe(`{"response_message_id":321,"p":"response/status","v":"FINISHED"}`)
	if state.shouldResume(false) {
		t.Fatal("a thinking-only reply is not empty")
	}

	state = &continueState{sessionID: "session-123"}
	state.observe(`{"v":"UG"}`)
	state.observe(`{"response_message_id":321,"p":"response/status","v":"FINISHED"}`)
	if state.shouldResume(false) {
		t.Fatal("a bare-string append is not empty")
	}

	// quasi_status FINISHED alone never triggers a resume: only the reply's own
	// status does (an interrupted batch status is not a finished message).
	state = &continueState{sessionID: "session-123"}
	state.observe(`{"response_message_id":321,"p":"response/quasi_status","v":"FINISHED"}`)
	if state.shouldResume(false) {
		t.Fatal("quasi_status must not trigger a resume")
	}
}

func TestShouldResumeOnlyOnce(t *testing.T) {
	state := &continueState{sessionID: "session-123"}
	state.observe(`{"response_message_id":321,"p":"response/status","v":"FINISHED"}`)
	if !state.shouldResume(false) {
		t.Fatal("expected the empty reply to be resumable")
	}
	if state.shouldResume(true) {
		t.Fatal("a reply must be re-read at most once")
	}
}

// An empty reply is re-read before its FINISHED frame reaches the consumer:
// both consumers stop reading at that frame, so forwarding it first would make
// the resumed content unreadable.
func TestAutoContinueWithholdsFinishedUntilResumeIsDecided(t *testing.T) {
	initialBody := `data: {"response_message_id":9,"p":"response/status","o":"SET","v":"FINISHED"}` + "\n" +
		`data: [DONE]` + "\n"

	var resumeCalls atomic.Int32
	body := newAutoContinueBody(context.Background(), io.NopCloser(strings.NewReader(initialBody)), "session-9", 8, func(context.Context, string, int) (*http.Response, error) {
		return nil, errors.New("continue should not have been called for an empty finished reply")
	}, func(context.Context, string, int) (*http.Response, error) {
		resumeCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`data: {"p":"response/content","v":"resumed answer"}` + "\n" +
					`data: {"p":"response/status","o":"SET","v":"FINISHED"}` + "\n" +
					`data: [DONE]` + "\n",
			)),
		}, nil
	})
	defer func() { _ = body.Close() }()

	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if resumeCalls.Load() != 1 {
		t.Fatalf("expected exactly one resume call, got %d", resumeCalls.Load())
	}
	contentAt := strings.Index(string(out), "resumed answer")
	finishedAt := strings.Index(string(out), `"v":"FINISHED"`)
	if contentAt < 0 {
		t.Fatalf("expected the resumed content in the body, got=%s", string(out))
	}
	if finishedAt < 0 {
		t.Fatalf("expected exactly one FINISHED frame in the body, got=%s", string(out))
	}
	if finishedAt < contentAt {
		t.Fatalf("FINISHED was forwarded before the resumed content: %s", string(out))
	}
	if got := strings.Count(string(out), `"v":"FINISHED"`); got != 1 {
		t.Fatalf("expected one FINISHED frame, got %d in %s", got, string(out))
	}
	if got := strings.Count(string(out), "data: [DONE]"); got != 1 {
		t.Fatalf("expected one DONE sentinel, got %d", got)
	}
}

// A resume that fails still lets the turn finish: the withheld frame is
// released so the consumer sees the empty-but-finished reply it expected.
func TestAutoContinueReleasesFinishedWhenResumeFails(t *testing.T) {
	initialBody := `data: {"response_message_id":9,"p":"response/status","o":"SET","v":"FINISHED"}` + "\n" +
		`data: [DONE]` + "\n"

	body := newAutoContinueBody(context.Background(), io.NopCloser(strings.NewReader(initialBody)), "session-9", 8, func(context.Context, string, int) (*http.Response, error) {
		return nil, errors.New("continue should not have been called")
	}, func(context.Context, string, int) (*http.Response, error) {
		return nil, errors.New("resume unavailable")
	})
	defer func() { _ = body.Close() }()

	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if !bytes.Contains(out, []byte(`"v":"FINISHED"`)) {
		t.Fatalf("expected the withheld FINISHED frame to be released, got=%s", string(out))
	}
	if !bytes.Contains(out, []byte(`data: [DONE]`)) {
		t.Fatalf("expected the DONE sentinel, got=%s", string(out))
	}
}

// Without a resume endpoint the stream is forwarded exactly as before.
func TestAutoContinueForwardsFinishedWhenResumeIsNotWired(t *testing.T) {
	initialBody := `data: {"response_message_id":9,"p":"response/status","o":"SET","v":"FINISHED"}` + "\n" +
		`data: [DONE]` + "\n"

	body := newAutoContinueBody(context.Background(), io.NopCloser(strings.NewReader(initialBody)), "session-9", 8, func(context.Context, string, int) (*http.Response, error) {
		return nil, errors.New("continue should not have been called")
	}, nil)
	defer func() { _ = body.Close() }()

	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if !bytes.Contains(out, []byte(`"v":"FINISHED"`)) {
		t.Fatalf("expected FINISHED to pass through, got=%s", string(out))
	}
}
