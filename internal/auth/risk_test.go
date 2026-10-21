package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"ds2api/internal/account"
	"ds2api/internal/config"
)

// A device/risk refusal is about the gateway's own exit, not about one account:
// the account is parked rather than retired, and no further sign-in is attempted
// while the breaker is open.
func TestRiskRefusalParksAccountAndOpensBreaker(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[
			{"email":"a@example.com","password":"pwd"},
			{"email":"b@example.com","password":"pwd"}
		]
	}`, func(int32) (string, error) {
		return "", NewLoginError(LoginCodeDevice, "RISK_DEVICE_DETECTED")
	})

	acc := h.account("a@example.com")
	err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonRequest)
	if err == nil {
		t.Fatal("expected the refusal to surface")
	}
	if !errors.Is(err, ErrRiskCooldown) {
		t.Fatalf("expected a risk cooldown error, got %v", err)
	}

	parked := h.account("a@example.com")
	if parked.Disabled {
		t.Fatal("a device refusal must not retire the account")
	}
	if parked.CooldownUntil <= float64(time.Now().Unix()) {
		t.Fatalf("expected a cooldown in the future, got %v", parked.CooldownUntil)
	}
	if parked.RefreshError == "" {
		t.Fatal("expected the reason to be recorded")
	}

	// The breaker is global: a different account does not get a turn either.
	before := h.logins.Load()
	second := h.account("b@example.com")
	if err := h.resolver.RefreshAccountToken(context.Background(), second, refreshReasonRequest); err == nil {
		t.Fatal("expected the breaker to refuse the second account")
	}
	if got := h.logins.Load(); got != before {
		t.Fatalf("expected no upstream attempt while the breaker is open, got %d", got-before)
	}

	// And the sweeper stays quiet too.
	h.resolver.sweepTokens(context.Background())
	if got := h.logins.Load(); got != before {
		t.Fatalf("expected the sweeper to skip during the breaker, got %d", got-before)
	}
}

// The first accepted sign-in closes the breaker.
func TestRiskCooldownClearsAfterSuccessfulLogin(t *testing.T) {
	var attempt int32
	h := newRefreshHarness(t, `{"accounts":[{"email":"a@example.com","password":"pwd"}]}`,
		func(n int32) (string, error) {
			if n == 1 {
				return "", NewLoginError(LoginCodeDevice, "RISK_DEVICE_DETECTED")
			}
			return "fresh-token", nil
		})

	acc := h.account("a@example.com")
	if err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonManual); err == nil {
		t.Fatal("expected the first attempt to be refused")
	}
	if h.resolver.riskCooldownRemaining() <= 0 {
		t.Fatal("expected the breaker to be open")
	}

	// Expire the window without waiting for it.
	h.resolver.riskMu.Lock()
	h.resolver.riskUntil = time.Now().Add(-time.Second)
	h.resolver.riskMu.Unlock()

	acc = h.account("a@example.com")
	if err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonManual); err != nil {
		t.Fatalf("expected the retry to succeed: %v", err)
	}
	if h.resolver.riskCooldownRemaining() != 0 {
		t.Fatal("expected a successful sign-in to close the breaker")
	}
	_ = attempt
}

// A mute parks the account for a while instead of retiring it: being muted is a
// rest, and the account comes back on its own.
func TestMutedRefusalParksAccount(t *testing.T) {
	h := newRefreshHarness(t, `{"accounts":[{"email":"a@example.com","password":"pwd"}]}`,
		func(int32) (string, error) {
			return "", NewLoginError(LoginCodeMuted, "account is muted")
		})

	acc := h.account("a@example.com")
	if err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonRequest); err == nil {
		t.Fatal("expected the refusal to surface")
	}
	parked := h.account("a@example.com")
	if parked.Disabled {
		t.Fatal("a mute must not retire the account")
	}
	if parked.CooldownUntil <= float64(time.Now().Unix()) {
		t.Fatalf("expected a cooldown, got %v", parked.CooldownUntil)
	}
}

// Wrong credentials and an upstream ban are the two refusals that really are
// per-account: they retire it until an operator acts.
func TestCredentialRefusalRetiresAccount(t *testing.T) {
	h := newRefreshHarness(t, `{"accounts":[{"email":"a@example.com","password":"wrong"}]}`,
		func(int32) (string, error) {
			return "", NewLoginError(LoginCodeCredentials, "PASSWORD_OR_USER_NAME_IS_WRONG")
		})

	acc := h.account("a@example.com")
	if err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonRequest); err == nil {
		t.Fatal("expected the refusal to surface")
	}
	retired := h.account("a@example.com")
	if !retired.Disabled {
		t.Fatal("expected wrong credentials to retire the account")
	}
	if retired.DisabledReason == "" {
		t.Fatal("expected the reason to be recorded")
	}
}

// The sweeper must never sign in a cold pool: after a restart every account has
// no token, and signing all of them in at once is what triggers the refusal the
// breaker then has to absorb.
func TestSweepNeverSignsInColdAccounts(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[
			{"email":"a@example.com","password":"pwd"},
			{"email":"b@example.com","password":"pwd"},
			{"email":"c@example.com","password":"pwd"}
		],
		"runtime":{"token_refresh_interval_hours":6}
	}`, func(int32) (string, error) { return "fresh", nil })

	h.resolver.sweepTokens(context.Background())
	if got := h.logins.Load(); got != 0 {
		t.Fatalf("expected no boot-time sign-ins, got %d", got)
	}
}

func TestClientErrorStatusMapping(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{name: "no account", err: ErrNoAccount, status: http.StatusTooManyRequests},
		{name: "risk cooldown", err: &RiskCooldownError{Until: time.Now().Add(time.Minute), Cause: errRiskCause}, status: http.StatusServiceUnavailable},
		{name: "terminal refusal", err: NewLoginError(LoginCodeDevice, "RISK_DEVICE_DETECTED"), status: http.StatusServiceUnavailable},
		{name: "bad direct token", err: ErrUnauthorized, status: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		status, message := ClientErrorStatus(tc.err)
		if status != tc.status {
			t.Fatalf("%s: status=%d want=%d", tc.name, status, tc.status)
		}
		if message == "" {
			t.Fatalf("%s: expected a message", tc.name)
		}
	}
	// The upstream refusal text must not reach the client.
	if _, message := ClientErrorStatus(NewLoginError(LoginCodeDevice, "RISK_DEVICE_DETECTED")); message == "login refused (11): RISK_DEVICE_DETECTED" {
		t.Fatal("upstream refusal text leaked into the client message")
	}
}

var _ = config.Account{}

// While the breaker is open a request does not even walk the pool: it gets the
// cooldown answer immediately (rendered as 503 by the handlers).
func TestDetermineFailsFastDuringRiskCooldown(t *testing.T) {
	t.Setenv("DS2API_CONFIG_JSON", `{
		"keys":["managed-key"],
		"accounts":[{"email":"a@example.com","password":"pwd"}]
	}`)
	store := config.LoadStore()
	pool := account.NewPool(store)
	r := NewResolver(store, pool, func(context.Context, config.Account) (string, error) {
		t.Fatal("the pool must not be consulted during a cooldown")
		return "", nil
	})
	r.enterRiskCooldown()

	req, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("x-api-key", "managed-key")
	_, err := r.Determine(req)
	if err == nil {
		t.Fatal("expected the cooldown to reject the request")
	}
	if !errors.Is(err, ErrRiskCooldown) {
		t.Fatalf("expected a risk cooldown error, got %v", err)
	}
	if status, _ := ClientErrorStatus(err); status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for a cooldown, got %d", status)
	}
}
