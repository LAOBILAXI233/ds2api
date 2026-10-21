package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"ds2api/internal/auth"
	"ds2api/internal/config"
	dsclient "ds2api/internal/deepseek/client"
)

type tokenImportDSMock struct {
	user  *dsclient.CurrentUser
	err   error
	seen  string
	login int
}

func (m *tokenImportDSMock) Login(context.Context, config.Account) (string, error) {
	m.login++
	return "", errors.New("password login must not be used by token import")
}

func (m *tokenImportDSMock) CreateSession(context.Context, *auth.RequestAuth, int) (string, error) {
	return "", nil
}

func (m *tokenImportDSMock) GetPow(context.Context, *auth.RequestAuth, int) (string, error) {
	return "", nil
}

func (m *tokenImportDSMock) CallCompletion(context.Context, *auth.RequestAuth, map[string]any, string, int) (*http.Response, error) {
	return nil, nil
}

func (m *tokenImportDSMock) GetSessionCountForToken(context.Context, string) (*dsclient.SessionStats, error) {
	return nil, nil
}

func (m *tokenImportDSMock) DeleteAllSessionsForToken(context.Context, string) error { return nil }

func (m *tokenImportDSMock) ValidateToken(_ context.Context, token, _ string) (*dsclient.CurrentUser, error) {
	m.seen = token
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

func TestImportAccountTokenCreatesAccountFromLiveToken(t *testing.T) {
	mock := &tokenImportDSMock{user: &dsclient.CurrentUser{ID: "u-1", Email: "fresh@example.com", Token: "live-token"}}
	router := newHTTPAdminHarness(t, `{"accounts":[]}`, mock)

	body, _ := json.Marshal(map[string]any{"token": "live-token", "name": "imported"})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adminReq(http.MethodPost, "/accounts/import-token", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
	}
	if mock.seen != "live-token" {
		t.Fatalf("expected the token to be validated, got %q", mock.seen)
	}
	if mock.login != 0 {
		t.Fatalf("token import must not run a password login")
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created, _ := payload["created"].(bool); !created {
		t.Fatalf("expected created=true, got %#v", payload)
	}
	if payload["identifier"] != "fresh@example.com" {
		t.Fatalf("unexpected identifier: %#v", payload["identifier"])
	}
}

func TestImportAccountTokenRetokensExistingAccountAndClearsBan(t *testing.T) {
	raw := `{"accounts":[{"email":"known@example.com","password":"pwd","banned":true,"disabled":true}]}`
	mock := &tokenImportDSMock{user: &dsclient.CurrentUser{ID: "u-2", Email: "KNOWN@example.com", Token: "new-live"}}
	router := newHTTPAdminHarness(t, raw, mock)

	body, _ := json.Marshal(map[string]any{"token": "new-live"})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adminReq(http.MethodPost, "/accounts/import-token", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if updated, _ := payload["updated"].(bool); !updated {
		t.Fatalf("expected updated=true, got %#v", payload)
	}
}

func TestImportAccountTokenRejectsRefusedToken(t *testing.T) {
	mock := &tokenImportDSMock{err: errors.New("token is not a live session")}
	router := newHTTPAdminHarness(t, `{"accounts":[]}`, mock)

	body, _ := json.Marshal(map[string]any{"token": "dead-token"})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adminReq(http.MethodPost, "/accounts/import-token", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if detail, _ := payload["detail"].(string); detail == "" {
		t.Fatalf("expected a detail message, got %#v", payload)
	}
}
