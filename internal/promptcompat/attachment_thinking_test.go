package promptcompat

import "testing"

// The web client's server rule: a turn carrying file references runs with
// thinking off. A request that asks for both is lowered to the shape the page
// itself sends.
func TestNormalizeOpenAIChatRequestTurnsThinkingOffForAttachmentTurns(t *testing.T) {
	req := map[string]any{
		"model": "deepseek-v4-flash",
		"messages": []any{
			map[string]any{"role": "user", "content": "look at this"},
		},
		"ref_file_ids": []any{"file-1"},
	}
	stdReq, err := NormalizeOpenAIChatRequest(stubStore{}, req, "trace")
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if stdReq.Thinking {
		t.Fatal("expected thinking to be off for an attachment turn")
	}
	if len(stdReq.RefFileIDs) != 1 {
		t.Fatalf("expected the attachment to survive, got %#v", stdReq.RefFileIDs)
	}
	payload := stdReq.CompletionPayload("session-1")
	if thinking, _ := payload["thinking_enabled"].(bool); thinking {
		t.Fatalf("payload must not enable thinking with files: %#v", payload["thinking_enabled"])
	}
}

func TestNormalizeOpenAIChatRequestKeepsThinkingWithoutAttachments(t *testing.T) {
	req := map[string]any{
		"model": "deepseek-v4-flash",
		"messages": []any{
			map[string]any{"role": "user", "content": "hello"},
		},
	}
	stdReq, err := NormalizeOpenAIChatRequest(stubStore{}, req, "trace")
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if !stdReq.Thinking {
		t.Fatal("expected thinking to stay on without attachments")
	}
}

type stubStore struct{}

func (stubStore) ModelAliases() map[string]string { return nil }
func (stubStore) AutoRouteVisionEnabled() bool    { return false }
