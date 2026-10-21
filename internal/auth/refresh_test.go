package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ds2api/internal/account"
	"ds2api/internal/config"
)

type refreshHarness struct {
	resolver *Resolver
	store    *config.Store
	logins   atomic.Int32
	mutex    sync.Mutex
	// loginFn decides each sign-in's result.
	loginFn func(n int32) (string, error)
}

func newRefreshHarness(t *testing.T, configJSON string, loginFn func(n int32) (string, error)) *refreshHarness {
	t.Helper()
	t.Setenv("DS2API_CONFIG_JSON", configJSON)
	store := config.LoadStore()
	h := &refreshHarness{store: store, loginFn: loginFn}
	h.resolver = NewResolver(store, account.NewPool(store), func(_ context.Context, _ config.Account) (string, error) {
		n := h.logins.Add(1)
		h.mutex.Lock()
		defer h.mutex.Unlock()
		return h.loginFn(n)
	})
	return h
}

func (h *refreshHarness) account(identifier string) config.Account {
	acc, _ := h.store.FindAccount(identifier)
	return acc
}

// A burst of requests sharing one revoked token must produce exactly one
// sign-in: the single-flight gate is what keeps a revoked token from turning
// into a login storm.
func TestRefreshTokenIsSingleFlight(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[{"email":"a@example.com","password":"pwd","token":"revoked"}]
	}`, func(n int32) (string, error) {
		time.Sleep(80 * time.Millisecond)
		return "fresh-" + string(rune('0'+n)), nil
	})

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			acc := h.account("a@example.com")
			errs[index] = h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonRequest)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d failed: %v", i, err)
		}
	}
	if got := h.logins.Load(); got != 1 {
		t.Fatalf("expected one sign-in for %d waiting requests, got %d", goroutines, got)
	}
	acc := h.account("a@example.com")
	if acc.Token != "fresh-1" {
		t.Fatalf("expected the refreshed token to be persisted, got %q", acc.Token)
	}
	if acc.TokenRefreshedAt <= 0 {
		t.Fatal("expected the refresh time to be recorded")
	}
	if acc.RefreshFailures != 0 {
		t.Fatalf("expected a clean failure slate, got %d", acc.RefreshFailures)
	}
}

// An account-level refusal retires the account at once and is never retried.
func TestRefreshDisablesOnTerminalRefusal(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[{"email":"a@example.com","password":"pwd"}]
	}`, func(int32) (string, error) {
		return "", NewLoginError(LoginCodeBanned, "USER_IS_BANNED")
	})

	acc := h.account("a@example.com")
	err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonScheduled)
	if err == nil {
		t.Fatal("expected the refusal to surface")
	}
	if !IsTerminalLoginError(err) {
		t.Fatalf("expected a terminal error, got %v", err)
	}
	got := h.account("a@example.com")
	if !got.Disabled || !got.Banned {
		t.Fatalf("expected a disabled+banned account, got disabled=%v banned=%v", got.Disabled, got.Banned)
	}
	if got.DisabledReason == "" {
		t.Fatal("expected the reason to be recorded")
	}

	// A terminal refusal must not be retried by the sweeper.
	h.resolver.sweepTokens(context.Background())
	if n := h.logins.Load(); n != 1 {
		t.Fatalf("expected the terminal refusal not to be retried, got %d sign-ins", n)
	}
}

// A transient failure backs off and retires the account only after three
// consecutive attempts — one bad minute must not cost an account.
func TestRefreshRetriesTransientFailuresThenDisables(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[{"email":"a@example.com","password":"pwd"}]
	}`, func(int32) (string, error) {
		return "", errors.New("network unreachable")
	})

	acc := h.account("a@example.com")
	if err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonScheduled); err == nil {
		t.Fatal("expected the failure to surface")
	}
	afterFirst := h.account("a@example.com")
	if afterFirst.Disabled {
		t.Fatal("one failure must not disable the account")
	}
	if afterFirst.RefreshFailures != 1 {
		t.Fatalf("expected one recorded failure, got %d", afterFirst.RefreshFailures)
	}
	if afterFirst.RefreshRetryAt <= float64(time.Now().Unix()) {
		t.Fatalf("expected a backoff deadline in the future, got %v", afterFirst.RefreshRetryAt)
	}

	// Inside the backoff window the sweeper must not hammer the login endpoint.
	h.resolver.sweepTokens(context.Background())
	if got := h.logins.Load(); got != 1 {
		t.Fatalf("expected the backoff to suppress the sweep, got %d sign-ins", got)
	}

	// Two more failures reach the three-strike limit.
	for i := 0; i < 2; i++ {
		_ = h.store.Update(func(c *config.Config) error {
			for j := range c.Accounts {
				c.Accounts[j].RefreshRetryAt = 0
			}
			return nil
		})
		acc = h.account("a@example.com")
		_ = h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonScheduled)
	}
	final := h.account("a@example.com")
	if !final.Disabled {
		t.Fatalf("expected three consecutive failures to disable the account, got %#v", final)
	}
	if final.RefreshError == "" {
		t.Fatal("expected the failure reason to be recorded")
	}
}

// A success clears the failure bookkeeping so a recovered account is clean.
func TestRefreshSuccessClearsFailures(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[{"email":"a@example.com","password":"pwd","refresh_failures":2,"refresh_error":"boom","refresh_retry_at":1}]
	}`, func(int32) (string, error) { return "fresh", nil })

	acc := h.account("a@example.com")
	if err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonManual); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	got := h.account("a@example.com")
	if got.RefreshFailures != 0 || got.RefreshError != "" || got.RefreshRetryAt != 0 {
		t.Fatalf("expected a clean slate, got %#v", got)
	}
	if got.Token != "fresh" {
		t.Fatalf("expected the new token, got %q", got.Token)
	}
}

// A token older than the interval is replaced; a token inside the interval is
// left alone (a sweep must not sign in for no reason).
func TestSweepRefreshesOnlyAgedTokens(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[
			{"email":"old@example.com","password":"pwd","token":"t-old"},
			{"email":"new@example.com","password":"pwd","token":"t-new"}
		],
		"runtime":{"token_refresh_interval_hours":6}
	}`, func(n int32) (string, error) { return "refreshed", nil })

	// The env config drops tokens on load (they are runtime state), so the
	// tokens this test sweeps are seeded the way a running gateway would hold
	// them.
	for identifier, token := range map[string]string{"old@example.com": "t-old", "new@example.com": "t-new"} {
		if err := h.store.UpdateAccountToken(identifier, token); err != nil {
			t.Fatalf("seed token failed: %v", err)
		}
	}
	_ = h.store.Update(func(c *config.Config) error {
		for i := range c.Accounts {
			switch c.Accounts[i].Email {
			case "old@example.com":
				c.Accounts[i].TokenRefreshedAt = float64(time.Now().Add(-7 * time.Hour).Unix())
			case "new@example.com":
				c.Accounts[i].TokenRefreshedAt = float64(time.Now().Add(-1 * time.Hour).Unix())
			}
		}
		return nil
	})

	h.resolver.sweepTokens(context.Background())
	if got := h.logins.Load(); got != 1 {
		t.Fatalf("expected exactly one refresh, got %d", got)
	}
	if h.account("old@example.com").Token != "refreshed" {
		t.Fatal("expected the old token to be replaced")
	}
	if h.account("new@example.com").Token != "t-new" {
		t.Fatal("expected the fresh token to be kept")
	}
}

// An unaged token is validated instead of replaced: /users/current is cheap and
// keeps an upgrade from signing in to every account.
func TestSweepValidatesUnagedTokensWithoutLogin(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[{"email":"a@example.com","password":"pwd","token":"live-token"}]
	}`, func(int32) (string, error) { return "should-not-login", nil })

	if err := h.store.UpdateAccountToken("a@example.com", "live-token"); err != nil {
		t.Fatalf("seed token failed: %v", err)
	}

	var validated int32
	h.resolver.Validate = func(_ context.Context, _ config.Account, token string) error {
		atomic.AddInt32(&validated, 1)
		if token != "live-token" {
			t.Fatalf("unexpected token %q", token)
		}
		return nil
	}

	h.resolver.sweepTokens(context.Background())
	if got := h.logins.Load(); got != 0 {
		t.Fatalf("a valid token must not be replaced, got %d sign-ins", got)
	}
	if atomic.LoadInt32(&validated) != 1 {
		t.Fatalf("expected one validation, got %d", validated)
	}
	acc := h.account("a@example.com")
	if acc.TokenRefreshedAt <= 0 {
		t.Fatal("expected validation to stamp the token age")
	}
	if acc.Token != "live-token" {
		t.Fatalf("expected the token to be kept, got %q", acc.Token)
	}
}

// A token that fails validation is replaced by a sign-in.
func TestSweepReplacesInvalidUnagedToken(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[{"email":"a@example.com","password":"pwd","token":"dead-token"}]
	}`, func(int32) (string, error) { return "fresh-token", nil })

	if err := h.store.UpdateAccountToken("a@example.com", "dead-token"); err != nil {
		t.Fatalf("seed token failed: %v", err)
	}
	h.resolver.Validate = func(context.Context, config.Account, string) error {
		return NewLoginError(0, "401 invalid token")
	}

	h.resolver.sweepTokens(context.Background())
	if got := h.logins.Load(); got != 1 {
		t.Fatalf("expected one sign-in after a dead token, got %d", got)
	}
	if h.account("a@example.com").Token != "fresh-token" {
		t.Fatal("expected the dead token to be replaced")
	}
}

// The endpoint-facing entry point adopts a token another goroutine just stored
// instead of paying for a second sign-in.
func TestRefreshAdoptsTokenStoredByAnotherGoroutine(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[{"email":"a@example.com","password":"pwd","token":"revoked"}]
	}`, func(int32) (string, error) { return "unexpected-login", nil })

	// The caller's snapshot is taken first, then the winner stamps a new token.
	snapshot := h.account("a@example.com")
	if err := h.store.MarkAccountRefreshed("a@example.com", "winner-token"); err != nil {
		t.Fatalf("mark refreshed failed: %v", err)
	}
	a := &RequestAuth{UseConfigToken: true, AccountID: "a@example.com", DeepSeekToken: "revoked"}
	a.Account = snapshot
	if err := h.resolver.refreshAccountToken(context.Background(), a, refreshReasonRequest); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if got := h.logins.Load(); got != 0 {
		t.Fatalf("expected the stored token to be adopted, got %d sign-ins", got)
	}
	if a.DeepSeekToken != "winner-token" {
		t.Fatalf("expected the stored token to be adopted, got %q", a.DeepSeekToken)
	}
}

// A manual re-login lifts a refresh retirement.
func TestClearRefreshBlockedReenablesAccount(t *testing.T) {
	h := newRefreshHarness(t, `{
		"accounts":[{"email":"a@example.com","password":"pwd","disabled":true,"disabled_reason":"bad"}]
	}`, func(int32) (string, error) { return "fresh", nil })

	if err := h.resolver.ClearRefreshBlocked("a@example.com"); err != nil {
		t.Fatalf("clear failed: %v", err)
	}
	acc := h.account("a@example.com")
	if acc.Disabled || acc.Banned || acc.DisabledReason != "" {
		t.Fatalf("expected the account to be schedulable again, got %#v", acc)
	}
}
