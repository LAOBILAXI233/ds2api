package signin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"ds2api/internal/auth"
)

type breakerStub struct {
	status  auth.RiskStatus
	cleared int
}

func (s *breakerStub) RiskStatus() auth.RiskStatus { return s.status }

func (s *breakerStub) ClearRisk() { s.cleared++ }

func newSigninHarness(t *testing.T, authValue any) http.Handler {
	t.Helper()
	h := &Handler{Auth: authValue}
	r := chi.NewRouter()
	RegisterRoutes(r, h)
	return r
}

func readPayload(t *testing.T, rec *httptest.ResponseRecorder) signinStatusPayload {
	t.Helper()
	var payload signinStatusPayload
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid payload %q: %v", rec.Body.String(), err)
	}
	return payload
}

func TestSigninRiskReportsOpenBreaker(t *testing.T) {
	until := time.Now().Add(12 * time.Minute)
	stub := &breakerStub{status: auth.RiskStatus{Active: true, Until: until, RemainingSeconds: 720, Strikes: 2}}
	router := newSigninHarness(t, stub)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/signin-risk", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
	}
	payload := readPayload(t, rec)
	if !payload.Supported || !payload.Active {
		t.Fatalf("expected an active supported breaker, got %#v", payload)
	}
	if payload.RemainingSeconds != 720 || payload.Strikes != 2 {
		t.Fatalf("unexpected breaker readings: %#v", payload)
	}
	if payload.Until == "" {
		t.Fatal("expected a deadline for the console to show")
	}
}

func TestSigninRiskIsQuietWithoutABreaker(t *testing.T) {
	router := newSigninHarness(t, nil)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/signin-risk", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
	}
	payload := readPayload(t, rec)
	if payload.Supported || payload.Active {
		t.Fatalf("expected an inert payload without a resolver, got %#v", payload)
	}
}

func TestSigninRiskClearCallsTheBreaker(t *testing.T) {
	stub := &breakerStub{status: auth.RiskStatus{Active: true, RemainingSeconds: 60}}
	router := newSigninHarness(t, stub)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/signin-risk/clear", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
	}
	if stub.cleared != 1 {
		t.Fatalf("expected one clear call, got %d", stub.cleared)
	}
}

func TestSigninRiskClearIsUnsupportedWithoutResolver(t *testing.T) {
	router := newSigninHarness(t, nil)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/signin-risk/clear", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
	}
}
