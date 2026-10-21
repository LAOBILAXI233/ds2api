package auth

// Token refresh
//
// A managed account's bearer token is a long-lived web session: it does not
// expire on a clock, it is revoked (logout, password change, risk measures) and
// then every request answers "invalid token". The refresh story is therefore
// event-driven, with a slow proactive sweep as a safety net:
//
//  1. a request that upstream refused as auth-related asks for a refresh; the
//     refresh is single-flight, so a burst of in-flight requests produces ONE
//     sign-in, not N;
//  2. a background sweeper refreshes tokens older than
//     `runtime.token_refresh_interval_hours` (default 6h) so a stale token is
//     replaced before it is ever used;
//  3. failures are classified (see login_error.go): an account-level refusal
//     disables the account immediately and is never retried, a transient one is
//     retried with exponential backoff and, after three consecutive failures,
//     disables the account with the reason recorded.
//
// The age of a token and the failure bookkeeping live in the account record, so
// a restart does not lose them: a process restart is not a reason to sign in to
// every account again (that is the one thing this project deliberately does NOT
// copy from ds-free-api, whose every-boot password login is the loudest possible
// traffic signature).

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"ds2api/internal/account"
	"ds2api/internal/config"
)

const (
	// defaultRefreshFailuresBeforeDisable mirrors ds-free-api's three-strike
	// rule: one bad minute or one network blip must not retire an account.
	defaultRefreshFailuresBeforeDisable = 3
	// refreshBackoffBase and refreshBackoffMax bound the retry spacing of a
	// transient failure (30s, 1m, 2m, … capped at 30m).
	refreshBackoffBase = 30 * time.Second
	refreshBackoffMax  = 30 * time.Minute
	// scheduledRefreshSpacing keeps a sweep over many accounts from looking like
	// a burst of sign-ins: accounts are refreshed one after another.
	scheduledRefreshSpacing = 300 * time.Millisecond
)

// refreshGate is the per-account single-flight lock.
type refreshGate struct {
	mu sync.Mutex
}

// refreshFailureKey / gate plumbing -------------------------------------------------

func (r *Resolver) gateFor(accountID string) *refreshGate {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if r.refreshGates == nil {
		r.refreshGates = map[string]*refreshGate{}
	}
	gate, ok := r.refreshGates[accountID]
	if !ok {
		gate = &refreshGate{}
		r.refreshGates[accountID] = gate
	}
	return gate
}

// refreshBackoff returns the delay before the next attempt after `failures`
// consecutive transient failures.
func refreshBackoff(failures int) time.Duration {
	if failures <= 1 {
		return refreshBackoffBase
	}
	backoff := refreshBackoffBase
	for i := 1; i < failures && backoff < refreshBackoffMax; i++ {
		backoff *= 2
	}
	if backoff > refreshBackoffMax {
		return refreshBackoffMax
	}
	return backoff
}

// tokenNeedsRefresh reports whether an account's stored token should be replaced
// before it is used again.
//
// `unknownAge` decides what to do with an account whose token age was never
// recorded (a config written by an older version): the sweeper treats it as due
// once, so the account is validated and stamped, while a request keeps using the
// stored token — a request must never pay for a sign-in it did not need.
func (r *Resolver) tokenNeedsRefresh(acc config.Account, unknownAge bool) bool {
	if strings.TrimSpace(acc.Token) == "" {
		return true
	}
	interval := r.Store.RuntimeTokenRefreshIntervalHours()
	if interval <= 0 {
		return false
	}
	if acc.RefreshRetryAt > float64(time.Now().Unix()) {
		return false
	}
	refreshedAt := acc.TokenRefreshedAt
	if refreshedAt <= 0 {
		return unknownAge
	}
	age := time.Since(time.Unix(int64(refreshedAt), 0))
	return age >= time.Duration(interval)*time.Hour
}

// refreshAccountToken signs in for one account exactly once across goroutines.
//
// The token that is already stored is kept until a new one arrives: clearing it
// first would turn one revoked token into a race where every waiting request
// believes the account has no token at all.
func (r *Resolver) refreshAccountToken(ctx context.Context, a *RequestAuth, reason string) error {
	if a == nil || a.AccountID == "" {
		return errNoAccountID
	}
	gate := r.gateFor(a.AccountID)
	gate.mu.Lock()
	defer gate.mu.Unlock()

	// Another goroutine may have refreshed while this one waited. Re-read the
	// account and use what the store now holds.
	if fresh, ok := r.Store.FindAccount(a.AccountID); ok {
		incoming := strings.TrimSpace(a.DeepSeekToken)
		stored := strings.TrimSpace(fresh.Token)
		// The caller's snapshot is what it came in with; the store may already
		// hold a token obtained by the goroutine that won the gate.
		callerStampedAt := a.Account.TokenRefreshedAt
		a.Account = fresh
		switch reason {
		case refreshReasonScheduled:
			if !r.tokenNeedsRefresh(fresh, true) {
				a.DeepSeekToken = stored
				return nil
			}
		case refreshReasonRequest:
			// A refresh that landed while this caller waited is adopted instead
			// of paying for a second sign-in: the token is new (it was stamped
			// after this caller's snapshot) and differs from what it used.
			if stored != "" && stored != incoming && fresh.TokenRefreshedAt > callerStampedAt {
				a.DeepSeekToken = stored
				return nil
			}
		}
	}

	if err := r.loginAndPersist(ctx, a); err != nil {
		r.recordRefreshFailure(a, err)
		return err
	}
	return nil
}

const (
	refreshReasonRequest   = "request"
	refreshReasonScheduled = "scheduled"
	refreshReasonManual    = "manual"
)

// recordRefreshFailure applies the failure policy: account-level refusals stop
// the account immediately, transient ones back off and are bounded.
func (r *Resolver) recordRefreshFailure(a *RequestAuth, err error) {
	identifier := ""
	if a != nil {
		identifier = a.AccountID
	}
	if identifier == "" {
		return
	}
	if loginErr, ok := AsLoginError(err); ok && loginErr.Terminal {
		reason := loginDisableReason(loginErr)
		config.Logger.Warn("[token_refresh] account refused at sign-in, disabling it",
			"account", identifier, "code", loginErr.Code, "reason", reason)
		r.disableAccountForRefresh(identifier, reason, loginErr.Code == LoginCodeBanned)
		return
	}

	failures := 1
	if a != nil {
		failures = a.Account.RefreshFailures + 1
	}
	retryAt := float64(time.Now().Add(refreshBackoff(failures)).Unix())
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	if failures >= defaultRefreshFailuresBeforeDisable {
		config.Logger.Error("[token_refresh] account failed to refresh repeatedly, disabling it",
			"account", identifier, "failures", failures, "error", reason)
		r.disableAccountForRefresh(identifier, "连续 "+strconv.Itoa(failures)+" 次刷新失败："+reason, false)
		return
	}
	config.Logger.Warn("[token_refresh] refresh failed, will retry",
		"account", identifier, "failures", failures, "retry_at", retryAt, "error", reason)
	r.persistRefreshFailure(identifier, reason, failures, retryAt)
	if a != nil {
		a.Account.RefreshFailures = failures
		a.Account.RefreshError = reason
		a.Account.RefreshRetryAt = retryAt
	}
}

// loginDisableReason turns a terminal refusal into an operator-readable reason.
func loginDisableReason(loginErr *LoginError) string {
	switch loginErr.Code {
	case LoginCodeCredentials:
		return "账号或密码错误（登录被拒，需人工核对凭据）"
	case LoginCodeMuted:
		return "账号被禁言/受限（登录被拒，需人工确认）"
	case LoginCodeBanned:
		return "账户已被停用（USER_IS_BANNED）"
	case LoginCodeDevice:
		return "设备校验未通过（device_id 可能已被标记）"
	default:
		return "登录被拒：" + loginErr.Message
	}
}

func (r *Resolver) persistRefreshFailure(identifier, reason string, failures int, retryAt float64) {
	if r == nil || r.Store == nil {
		return
	}
	if err := r.Store.MarkAccountRefreshFailure(identifier, reason, failures, retryAt); err != nil {
		config.Logger.Error("[token_refresh] persisting the refresh failure failed", "account", identifier, "error", err)
	}
}

// disableAccountForRefresh retires an account that cannot be refreshed. Banned
// keeps the existing meaning (upstream banned it), so the pool and the admin
// console treat "banned" and "cannot refresh" differently. An elastic pool is
// reconciled in the same transaction, so a standby takes the freed slot.
func (r *Resolver) disableAccountForRefresh(identifier, reason string, banned bool) {
	if r == nil || r.Store == nil || strings.TrimSpace(identifier) == "" {
		return
	}
	if err := r.Store.Update(func(c *config.Config) error {
		for i := range c.Accounts {
			if c.Accounts[i].Identifier() != identifier {
				continue
			}
			c.Accounts[i].Disabled = true
			c.Accounts[i].DisabledReason = strings.TrimSpace(reason)
			c.Accounts[i].RefreshError = strings.TrimSpace(reason)
			c.Accounts[i].RefreshRetryAt = 0
			// The token is either revoked or belongs to an account we may not
			// use; keeping it would only invite another refused request.
			c.Accounts[i].Token = ""
			c.Accounts[i].TokenRefreshedAt = 0
			if banned {
				c.Accounts[i].Banned = true
			}
			break
		}
		if c.ElasticPool.Enabled {
			account.ReconcileElasticPool(c)
		}
		return nil
	}); err != nil {
		config.Logger.Error("[token_refresh] persisting the disabled state failed", "account", identifier, "error", err)
		return
	}
	if r.Pool != nil {
		r.Pool.Reset()
	}
}

// ClearRefreshBlocked re-enables an account after a successful manual sign-in.
func (r *Resolver) ClearRefreshBlocked(identifier string) error {
	if r == nil || r.Store == nil {
		return errNoAccountID
	}
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return errNoAccountID
	}
	if err := r.Store.Update(func(c *config.Config) error {
		for i := range c.Accounts {
			if c.Accounts[i].Identifier() != identifier {
				continue
			}
			c.Accounts[i].Disabled = false
			c.Accounts[i].DisabledReason = ""
			c.Accounts[i].Banned = false
			c.Accounts[i].RefreshFailures = 0
			c.Accounts[i].RefreshError = ""
			c.Accounts[i].RefreshRetryAt = 0
			break
		}
		if c.ElasticPool.Enabled {
			account.ReconcileElasticPool(c)
		}
		return nil
	}); err != nil {
		return err
	}
	if r.Pool != nil {
		r.Pool.Reset()
	}
	return nil
}

// RefreshAccountToken is the public entry point: it refreshes one account now,
// single-flight, and reports what happened. The admin re-login endpoint and the
// sweeper both use it.
func (r *Resolver) RefreshAccountToken(ctx context.Context, acc config.Account, reason string) error {
	if r == nil || r.Store == nil {
		return errNoAccountID
	}
	a := &RequestAuth{
		UseConfigToken: true,
		AccountID:      acc.Identifier(),
		Account:        acc,
		TriedAccounts:  map[string]bool{},
	}
	if err := r.refreshAccountToken(ctx, a, reason); err != nil {
		return err
	}
	return nil
}

// StartTokenRefresher sweeps accounts forever, refreshing tokens that are older
// than the configured interval and retrying transient failures whose backoff
// has expired. It is the counterpart of ds-free-api's one-minute recovery task,
// with two differences that matter for risk control: a token that is still
// valid is never re-logged-in "just because", and a refused account is not
// retried at all.
func (r *Resolver) StartTokenRefresher(ctx context.Context, every time.Duration) {
	if r == nil || r.Store == nil {
		return
	}
	if every <= 0 {
		every = time.Minute
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	config.Logger.Info("[token_refresh] sweeper started", "interval", every.String(), "token_age_hours", r.Store.RuntimeTokenRefreshIntervalHours())
	for {
		select {
		case <-ctx.Done():
			config.Logger.Info("[token_refresh] sweeper stopped")
			return
		case <-ticker.C:
			r.sweepTokens(ctx)
		}
	}
}

// sweepTokens runs one pass over the configured accounts.
//
// A token whose age was never recorded is *validated*, not replaced: one cheap
// GET /users/current (no proof of work, no chat) says whether it is still a live
// session and stamps its age. Only a token that fails that check is replaced by
// a sign-in — the difference between this sweeper and a login storm.
func (r *Resolver) sweepTokens(ctx context.Context) {
	accounts := r.Store.Accounts()
	validated, refreshed, skipped, failed := 0, 0, 0, 0
	for _, acc := range accounts {
		if ctx.Err() != nil {
			return
		}
		if !acc.IsEnabled() || acc.IsBanned() || acc.Identifier() == "" {
			continue
		}
		if acc.RefreshRetryAt > float64(time.Now().Unix()) {
			skipped++
			continue
		}
		if strings.TrimSpace(acc.Token) != "" && acc.TokenRefreshedAt <= 0 && r.Validate != nil {
			switch err := r.validateStoredToken(ctx, acc); {
			case err == nil:
				validated++
			case IsTerminalLoginError(err):
				failed++
			default:
				// The stored token is not a live session (or the check itself
				// failed): fall through to a real refresh.
				if refreshErr := r.RefreshAccountToken(ctx, acc, refreshReasonScheduled); refreshErr != nil {
					failed++
				} else {
					refreshed++
				}
			}
			r.spaceSweep(ctx)
			continue
		}
		if !r.tokenNeedsRefresh(acc, true) {
			skipped++
			continue
		}
		if err := r.RefreshAccountToken(ctx, acc, refreshReasonScheduled); err != nil {
			failed++
		} else {
			refreshed++
		}
		// Space the sweep out: a pool of N accounts must not sign in as one burst.
		r.spaceSweep(ctx)
	}
	if validated > 0 || refreshed > 0 || failed > 0 {
		config.Logger.Info("[token_refresh] sweep finished",
			"validated", validated, "refreshed", refreshed, "failed", failed, "skipped", skipped)
	}
}

// validateStoredToken asks whether a stored token is still a live session and,
// when it is, records its age so it is not re-checked on every sweep.
func (r *Resolver) validateStoredToken(ctx context.Context, acc config.Account) error {
	if err := r.Validate(ctx, acc, strings.TrimSpace(acc.Token)); err != nil {
		// A token that is not a live session is not a refresh failure: it is
		// the reason the sweep is about to sign in. Counting it would make the
		// token look like an unreachable login endpoint.
		config.Logger.Debug("[token_refresh] stored token is not a live session", "account", acc.Identifier(), "error", err)
		return err
	}
	if err := r.Store.MarkAccountRefreshed(acc.Identifier(), strings.TrimSpace(acc.Token)); err != nil {
		config.Logger.Warn("[token_refresh] stamping the validated token failed", "account", acc.Identifier(), "error", err)
	}
	return nil
}

func (r *Resolver) spaceSweep(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(scheduledRefreshSpacing):
	}
}

var errNoAccountID = errString("managed account has no identifier")

type errString string

func (e errString) Error() string { return string(e) }
