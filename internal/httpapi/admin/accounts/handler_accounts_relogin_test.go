package accounts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"ds2api/internal/account"
	"ds2api/internal/auth"
	"ds2api/internal/config"
)

type reloginStub struct {
	refreshErr error
	cleared    []string
	refreshed  []string
	refreshCtx context.Context
}

func (s *reloginStub) RefreshAccountToken(ctx context.Context, acc config.Account, _ string) error {
	s.refreshCtx = ctx
	s.refreshed = append(s.refreshed, acc.Identifier())
	return s.refreshErr
}

func (s *reloginStub) ClearRefreshBlocked(identifier string) error {
	s.cleared = append(s.cleared, identifier)
	return nil
}

func newReloginHarness(t *testing.T, rawConfig string, refresher any) http.Handler {
	t.Helper()
	t.Setenv("DS2API_CONFIG_JSON", rawConfig)
	store := config.LoadStore()
	h := &Handler{
		Store: store,
		Pool:  account.NewPool(store),
		Auth:  refresher,
	}
	r := chi.NewRouter()
	RegisterRoutes(r, h)
	return r
}

func TestReloginRefreshesAndClearsRetirement(t *testing.T) {
	stub := &reloginStub{}
	router := newReloginHarness(t, `{"accounts":[{"email":"a@example.com","password":"pwd","disabled":true}]}`, stub)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adminReq(http.MethodPost, "/accounts/a@example.com/relogin", []byte(`{}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
	}
	if len(stub.refreshed) != 1 || stub.refreshed[0] != "a@example.com" {
		t.Fatalf("expected one refresh for the account, got %#v", stub.refreshed)
	}
	if len(stub.cleared) != 1 {
		t.Fatalf("expected the retirement to be cleared, got %#v", stub.cleared)
	}
}

func TestReloginKeepsRetirementWhenClearIsFalse(t *testing.T) {
	stub := &reloginStub{}
	router := newReloginHarness(t, `{"accounts":[{"email":"a@example.com","password":"pwd"}]}`, stub)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adminReq(http.MethodPost, "/accounts/a@example.com/relogin", []byte(`{"clear":false}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
	}
	if len(stub.cleared) != 0 {
		t.Fatalf("expected no clearing, got %#v", stub.cleared)
	}
}

func TestReloginReportsTerminalRefusal(t *testing.T) {
	stub := &reloginStub{refreshErr: auth.NewLoginError(auth.LoginCodeBanned, "banned")}
	router := newReloginHarness(t, `{"accounts":[{"email":"a@example.com","password":"pwd"}]}`, stub)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adminReq(http.MethodPost, "/accounts/a@example.com/relogin", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if terminal, _ := payload["terminal"].(bool); !terminal {
		t.Fatalf("expected terminal=true, got %#v", payload)
	}
}

func TestReloginUnknownAccount(t *testing.T) {
	stub := &reloginStub{}
	router := newReloginHarness(t, `{"accounts":[]}`, stub)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adminReq(http.MethodPost, "/accounts/missing@example.com/relogin", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReloginWithoutResolverIsNotImplemented(t *testing.T) {
	router := newReloginHarness(t, `{"accounts":[{"email":"a@example.com","password":"pwd"}]}`, nil)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adminReq(http.MethodPost, "/accounts/a@example.com/relogin", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d body=%s", rec.Code, rec.Body.String())
	}
}
