package auth

// Upstream risk refusals
//
// DeepSeek can answer a sign-in with `RISK_DEVICE_DETECTED` (biz_code 11). That
// answer is not about one account's password: it is the risk layer judging the
// device/IP the request came from. Worth remembering:
//
//   - it is evaluated per account+device+IP, so when the proxy's own exit IP is
//     what got flagged, EVERY account answers 11 at once — the state this
//     project hit in production (31 accounts, one IP);
//   - each refusal is itself a signal. Retrying it account after account (one
//     request used to walk all 31) is what turns "one refusal" into "this IP
//     keeps hammering the login endpoint".
//
// So a refusal opens a global circuit breaker: no sign-in is attempted for a
// cooldown window, the accounts that were refused get a matching cooldown so the
// pool stops scheduling them, and the client gets a 503 that says the gateway
// has no usable account right now instead of a 401 that blames its API key.
// The breaker closes again on the first successful sign-in.

import (
	"errors"
	"net/http"
	"time"

	"ds2api/internal/config"
)

// ErrRiskCooldown marks "no sign-in will be attempted right now".
var ErrRiskCooldown = errors.New("upstream is refusing sign-ins for this deployment; backing off")

// errRiskCause is the wrapped cause when the breaker is what stopped the call.
var errRiskCause = errors.New("risk cooldown active")

// RiskCooldownError reports the breaker state and carries the upstream cause for
// the logs.
type RiskCooldownError struct {
	Until time.Time
	Cause error
}

func (e *RiskCooldownError) Error() string {
	if e == nil {
		return ErrRiskCooldown.Error()
	}
	message := "risk cooldown until " + e.Until.UTC().Format(time.RFC3339)
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

func (e *RiskCooldownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *RiskCooldownError) Is(target error) bool {
	return target == ErrRiskCooldown
}

const (
	riskCooldownBase = 10 * time.Minute
	riskCooldownMax  = 2 * time.Hour
)

// riskCooldownRemaining reports how long sign-ins stay blocked.
func (r *Resolver) riskCooldownRemaining() time.Duration {
	if r == nil {
		return 0
	}
	r.riskMu.Lock()
	defer r.riskMu.Unlock()
	if r.riskUntil.IsZero() {
		return 0
	}
	if remaining := time.Until(r.riskUntil); remaining > 0 {
		return remaining
	}
	return 0
}

// enterRiskCooldown opens (or extends) the breaker and returns its deadline.
// Consecutive refusals double the window so a stubborn IP stops being tried.
func (r *Resolver) enterRiskCooldown() time.Time {
	if r == nil {
		return time.Time{}
	}
	r.riskMu.Lock()
	defer r.riskMu.Unlock()
	r.riskStrikes++
	window := riskCooldownBase
	for i := 1; i < r.riskStrikes && window < riskCooldownMax; i++ {
		window *= 2
	}
	if window > riskCooldownMax {
		window = riskCooldownMax
	}
	until := time.Now().Add(window)
	r.riskUntil = until
	config.Logger.Warn("[token_refresh] upstream refused a sign-in as risky, pausing all sign-ins",
		"until", until.UTC().Format(time.RFC3339), "window", window.String(), "strikes", r.riskStrikes)
	return until
}

// clearRiskCooldown closes the breaker after a successful sign-in.
func (r *Resolver) clearRiskCooldown() {
	if r == nil {
		return
	}
	r.riskMu.Lock()
	defer r.riskMu.Unlock()
	if !r.riskUntil.IsZero() || r.riskStrikes > 0 {
		config.Logger.Info("[token_refresh] sign-in accepted again, closing the risk cooldown")
	}
	r.riskUntil = time.Time{}
	r.riskStrikes = 0
}

// RiskStatus is the sign-in breaker as the admin console has to show it: an
// operator looking at "no accounts available" needs to know whether the pool is
// empty or whether this deployment simply stopped signing in.
type RiskStatus struct {
	Active           bool
	Until            time.Time
	RemainingSeconds int
	Strikes          int
}

// RiskStatus reports the breaker state. The zero value means sign-ins are
// allowed.
func (r *Resolver) RiskStatus() RiskStatus {
	if r == nil {
		return RiskStatus{}
	}
	r.riskMu.Lock()
	defer r.riskMu.Unlock()
	status := RiskStatus{Strikes: r.riskStrikes}
	remaining := time.Until(r.riskUntil)
	if !r.riskUntil.IsZero() && remaining > 0 {
		status.Active = true
		status.Until = r.riskUntil
		status.RemainingSeconds = int((remaining + time.Second - 1) / time.Second)
	}
	return status
}

// ClearRisk lifts the breaker so the next caller retries a sign-in immediately.
// This is the operator's override — useful right after pointing the accounts at
// a different exit IP — and it deliberately does not reset the strike count:
// one manual retry should not make the next refusal start from 10 minutes again.
func (r *Resolver) ClearRisk() {
	if r == nil {
		return
	}
	r.riskMu.Lock()
	wasActive := !r.riskUntil.IsZero()
	r.riskUntil = time.Time{}
	r.riskMu.Unlock()
	if wasActive {
		config.Logger.Info("[token_refresh] operator lifted the sign-in risk cooldown")
	}
}

// ClientErrorStatus maps a Determine/refresh error to what the caller should see.
//
// A gateway that cannot sign in is an outage on this side, not a problem with
// the caller's API key: answering 401 here sends operators looking at the wrong
// credential, and the upstream text does not belong in a client response.
func ClientErrorStatus(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	if errors.Is(err, ErrNoAccount) {
		return http.StatusTooManyRequests, ErrNoAccount.Error()
	}
	if errors.Is(err, ErrRiskCooldown) {
		return http.StatusServiceUnavailable, "no usable account right now: upstream refused this gateway's sign-in; retry later"
	}
	if loginErr, ok := AsLoginError(err); ok {
		config.Logger.Warn("[auth] sign-in was refused for a managed account", "code", loginErr.Code, "terminal", loginErr.Terminal)
		return http.StatusServiceUnavailable, "no usable account right now: the upstream sign-in was refused"
	}
	return http.StatusUnauthorized, err.Error()
}

// applyAccountCooldown parks one account until `until` so the pool stops
// scheduling it, without retiring it: this is the recoverable counterpart of
// disabling, used for refusals that may simply be about the exit IP.
func (r *Resolver) applyAccountCooldown(identifier string, until time.Time, reason string) {
	if r == nil || r.Store == nil || identifier == "" || until.IsZero() {
		return
	}
	cooldown := float64(until.Unix())
	if err := r.Store.Update(func(c *config.Config) error {
		for i := range c.Accounts {
			if c.Accounts[i].Identifier() != identifier {
				continue
			}
			c.Accounts[i].CooldownUntil = cooldown
			c.Accounts[i].RefreshError = reason
			c.Accounts[i].RefreshRetryAt = cooldown
			c.Accounts[i].RefreshFailures = 0
			// The token was refused, so it is not worth keeping.
			c.Accounts[i].Token = ""
			c.Accounts[i].TokenRefreshedAt = 0
			break
		}
		return nil
	}); err != nil {
		config.Logger.Error("[token_refresh] persisting the account cooldown failed", "account", identifier, "error", err)
		return
	}
	if r.Pool != nil {
		r.Pool.Reset()
	}
}
