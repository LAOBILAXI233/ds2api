package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"ds2api/internal/account"
	"ds2api/internal/config"
)

type ctxKey string

const authCtxKey ctxKey = "auth_context"

const toolsDisabledCtxKey ctxKey = "tools_disabled"

var (
	ErrUnauthorized = errors.New("unauthorized: missing auth token")
	ErrNoAccount    = errors.New("no accounts configured or all accounts are busy")
)

type RequestAuth struct {
	UseConfigToken bool
	DeepSeekToken  string
	CallerID       string
	AccountID      string
	TargetAccount  string
	Account        config.Account
	TriedAccounts  map[string]bool
	ToolsEnabled   bool
	resolver       *Resolver
}

type LoginFunc func(ctx context.Context, acc config.Account) (string, error)
type PostLoginFunc func(ctx context.Context, a *RequestAuth)

// TokenValidator checks a stored token without signing in. A nil error means the
// token is a live session.
type TokenValidator func(ctx context.Context, acc config.Account, token string) error

type Resolver struct {
	Store     *config.Store
	Pool      *account.Pool
	Login     LoginFunc
	PostLogin PostLoginFunc
	// Validate asks whether a stored token is still a live session without
	// signing in. The DeepSeek client installs it (GET /users/current); a nil
	// validator means the sweeper only learns a token's state by signing in.
	Validate TokenValidator

	// refreshMu guards refreshGates: one gate per account makes token refresh
	// single-flight, so a burst of requests with a revoked token produces one
	// sign-in rather than one per request.
	refreshMu    sync.Mutex
	refreshGates map[string]*refreshGate

	// riskMu guards the sign-in circuit breaker (see risk.go): once upstream
	// answers a sign-in as risky, no further attempt is made until it expires.
	riskMu      sync.Mutex
	riskUntil   time.Time
	riskStrikes int
}

func NewResolver(store *config.Store, pool *account.Pool, login LoginFunc) *Resolver {
	return &Resolver{
		Store:        store,
		Pool:         pool,
		Login:        login,
		refreshGates: map[string]*refreshGate{},
	}
}

func (r *Resolver) Determine(req *http.Request) (*RequestAuth, error) {
	callerKey := extractCallerToken(req)
	if callerKey == "" {
		return nil, ErrUnauthorized
	}
	callerID := callerTokenID(callerKey)
	ctx := req.Context()
	if !r.Store.HasAPIKey(callerKey) {
		return &RequestAuth{
			UseConfigToken: false,
			DeepSeekToken:  callerKey,
			CallerID:       callerID,
			resolver:       r,
			TriedAccounts:  map[string]bool{},
		}, nil
	}
	target := strings.TrimSpace(req.Header.Get("X-Ds2-Target-Account"))
	toolsEnabled := r.Store.APIKeyToolsEnabled(callerKey)
	a, err := r.acquireManagedRequestAuth(ctx, callerID, target, toolsEnabled)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (r *Resolver) acquireManagedRequestAuth(ctx context.Context, callerID, target string, toolsEnabled bool) (*RequestAuth, error) {
	// While upstream is refusing sign-ins nothing here can succeed, and walking
	// the pool would only add more refusals: answer straight away with the
	// cooldown, which the handlers render as a 503.
	if remaining := r.riskCooldownRemaining(); remaining > 0 {
		return nil, &RiskCooldownError{Until: time.Now().Add(remaining), Cause: errRiskCause}
	}
	tried := map[string]bool{}
	var lastEnsureErr error
	filter := account.AccountFilter(func(acc config.Account) bool {
		return acc.MatchesPoolType(toolsEnabled)
	})
	for {
		if target == "" && len(tried) >= len(r.Store.Accounts()) {
			if lastEnsureErr != nil {
				return nil, lastEnsureErr
			}
			return nil, ErrNoAccount
		}
		acc, ok := r.Pool.AcquireWait(ctx, target, tried, filter)
		if !ok {
			if lastEnsureErr != nil {
				return nil, lastEnsureErr
			}
			return nil, ErrNoAccount
		}

		a := &RequestAuth{
			UseConfigToken: true,
			CallerID:       callerID,
			AccountID:      acc.Identifier(),
			TargetAccount:  target,
			Account:        acc,
			TriedAccounts:  tried,
			ToolsEnabled:   toolsEnabled,
			resolver:       r,
		}

		if err := r.ensureManagedToken(ctx, a); err != nil {
			lastEnsureErr = err
			tried[a.AccountID] = true
			r.Pool.Release(a.AccountID)
			if target != "" {
				return nil, err
			}
			continue
		}
		return a, nil
	}
}

// DetermineCaller resolves caller identity without acquiring any pooled account.
// Use this for local-cache lookup routes that only need tenant isolation.
func (r *Resolver) DetermineCaller(req *http.Request) (*RequestAuth, error) {
	callerKey := extractCallerToken(req)
	if callerKey == "" {
		return nil, ErrUnauthorized
	}
	callerID := callerTokenID(callerKey)
	a := &RequestAuth{
		UseConfigToken: false,
		CallerID:       callerID,
		resolver:       r,
		TriedAccounts:  map[string]bool{},
	}
	if r == nil || r.Store == nil || !r.Store.HasAPIKey(callerKey) {
		a.DeepSeekToken = callerKey
	}
	return a, nil
}

func WithAuth(ctx context.Context, a *RequestAuth) context.Context {
	return context.WithValue(ctx, authCtxKey, a)
}

func FromContext(ctx context.Context) (*RequestAuth, bool) {
	v := ctx.Value(authCtxKey)
	a, ok := v.(*RequestAuth)
	return a, ok
}

// ToolsEnabledForRequest reports whether tool-call prompt injection should
// happen for the caller behind req. Managed API keys with tools_enabled=false
// disable injection; direct-token callers and missing/unknown keys keep the
// default (enabled) behavior.
func (r *Resolver) ToolsEnabledForRequest(req *http.Request) bool {
	callerKey := extractCallerToken(req)
	if callerKey == "" {
		return true
	}
	if r == nil || r.Store == nil || !r.Store.HasAPIKey(callerKey) {
		return true
	}
	return r.Store.APIKeyToolsEnabled(callerKey)
}

// WithToolsDisabled stores a flag in the context so downstream consumers
// (e.g. current-input-file tool transcript generation) can skip tool handling.
func WithToolsDisabled(ctx context.Context) context.Context {
	return context.WithValue(ctx, toolsDisabledCtxKey, true)
}

// ToolsDisabledFromContext returns true when the caller's API key has
// tools_enabled=false and the request context was marked accordingly.
func ToolsDisabledFromContext(ctx context.Context) bool {
	v := ctx.Value(toolsDisabledCtxKey)
	b, _ := v.(bool)
	return b
}

func (r *Resolver) loginAndPersist(ctx context.Context, a *RequestAuth) error {
	token, err := r.Login(ctx, a.Account)
	if err != nil {
		return err
	}
	a.Account.Token = token
	a.Account.TokenRefreshedAt = float64(time.Now().Unix())
	a.Account.RefreshFailures = 0
	a.Account.RefreshError = ""
	a.Account.RefreshRetryAt = 0
	a.DeepSeekToken = token
	if err := r.Store.MarkAccountRefreshed(a.AccountID, token); err != nil {
		return err
	}
	if r.PostLogin != nil {
		r.PostLogin(ctx, a)
	}
	return nil
}

// RefreshToken replaces a token upstream refused. Unlike the old path it does
// not wipe the stored token first: the refresh is single-flight, so every
// waiting request re-reads the account afterwards and picks up whichever token
// the winning goroutine obtained.
func (r *Resolver) RefreshToken(ctx context.Context, a *RequestAuth) bool {
	if a == nil || !a.UseConfigToken || a.AccountID == "" {
		return false
	}
	if err := r.refreshAccountToken(ctx, a, refreshReasonRequest); err != nil {
		config.Logger.Error("[refresh_token] failed", "account", a.AccountID, "error", err)
		return false
	}
	return true
}

func (r *Resolver) MarkTokenInvalid(a *RequestAuth) {
	if !a.UseConfigToken || a.AccountID == "" {
		return
	}
	a.Account.Token = ""
	a.Account.TokenRefreshedAt = 0
	a.DeepSeekToken = ""
	_ = r.Store.UpdateAccountToken(a.AccountID, "")
}

// SetAccountMutedUntil 持久化账号禁言到期时间。
// 与 DisableAccount 不同，这只是临时禁用，到期后号池会自动恢复调度。
// 当弹性号池开启时，封号后立即在同一个事务内触发 ReconcileElasticPool
// 补位：被封账号让出名额，按原始顺序从后面的休眠账号中启用一个补上。
func (r *Resolver) SetAccountMutedUntil(a *RequestAuth, muteUntil float64) {
	if !a.UseConfigToken || a.AccountID == "" || muteUntil <= 0 {
		return
	}
	identifier := a.AccountID
	if err := r.Store.Update(func(c *config.Config) error {
		for i := range c.Accounts {
			if c.Accounts[i].Identifier() != identifier {
				continue
			}
			c.Accounts[i].MutedUntil = muteUntil
			break
		}
		if c.ElasticPool.Enabled {
			account.ReconcileElasticPool(c)
		}
		return nil
	}); err != nil {
		config.Logger.Error("[muted_account] failed to persist muted_until", "account", identifier, "error", err)
		return
	}
	a.Account.MutedUntil = muteUntil
	if r.Pool != nil {
		r.Pool.Reset()
	}
	config.Logger.Info("[muted_account] account muted until", "account", identifier, "mute_until", muteUntil)
}

// SetAccountBanned 将账号标记为被上游停用（USER_IS_BANNED）。
// 手动启用或启用全部账号不会解除该状态；只有成功刷新 token 后才会在 Login 中清除。
func (r *Resolver) SetAccountBanned(a *RequestAuth, reason string) {
	if !a.UseConfigToken || a.AccountID == "" {
		return
	}
	if strings.TrimSpace(reason) == "" {
		reason = "账户已被停用"
	}
	identifier := a.AccountID
	if err := r.Store.Update(func(c *config.Config) error {
		for i := range c.Accounts {
			if c.Accounts[i].Identifier() != identifier {
				continue
			}
			c.Accounts[i].Banned = true
			c.Accounts[i].Disabled = true
			c.Accounts[i].DisabledReason = reason
			break
		}
		if c.ElasticPool.Enabled {
			account.ReconcileElasticPool(c)
		}
		return nil
	}); err != nil {
		config.Logger.Error("[banned_account] failed to persist banned state", "account", identifier, "error", err)
		return
	}
	a.Account.Banned = true
	a.Account.Disabled = true
	a.Account.DisabledReason = reason
	if r.Pool != nil {
		r.Pool.Reset()
	}
	config.Logger.Warn("[banned_account] account disabled after USER_IS_BANNED", "account", identifier, "reason", reason)
}

func (r *Resolver) SwitchAccount(ctx context.Context, a *RequestAuth) bool {
	if !a.UseConfigToken {
		return false
	}
	if strings.TrimSpace(a.TargetAccount) != "" {
		return false
	}
	if a.TriedAccounts == nil {
		a.TriedAccounts = map[string]bool{}
	}
	if a.AccountID != "" {
		a.TriedAccounts[a.AccountID] = true
		r.Pool.Release(a.AccountID)
	}
	filter := account.AccountFilter(func(acc config.Account) bool {
		return acc.MatchesPoolType(a.ToolsEnabled)
	})
	for {
		acc, ok := r.Pool.Acquire("", a.TriedAccounts, filter)
		if !ok {
			return false
		}
		a.Account = acc
		a.AccountID = acc.Identifier()
		if err := r.ensureManagedToken(ctx, a); err != nil {
			a.TriedAccounts[a.AccountID] = true
			r.Pool.Release(a.AccountID)
			continue
		}
		return true
	}
}

func (a *RequestAuth) SwitchAccount(ctx context.Context) bool {
	if a == nil || a.resolver == nil {
		return false
	}
	return a.resolver.SwitchAccount(ctx, a)
}

func (r *Resolver) Release(a *RequestAuth) {
	if a == nil || !a.UseConfigToken || a.AccountID == "" {
		return
	}
	r.Pool.Release(a.AccountID)
}

func extractCallerToken(req *http.Request) string {
	authHeader := strings.TrimSpace(req.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		token := strings.TrimSpace(authHeader[7:])
		if token != "" {
			return token
		}
	}
	if key := strings.TrimSpace(req.Header.Get("x-api-key")); key != "" {
		return key
	}
	// Gemini/Google clients commonly send API key via x-goog-api-key.
	if key := strings.TrimSpace(req.Header.Get("x-goog-api-key")); key != "" {
		return key
	}
	// Gemini AI Studio compatibility: allow query key fallback only when no
	// header-based credential is present.
	if key := strings.TrimSpace(req.URL.Query().Get("key")); key != "" {
		return key
	}
	return strings.TrimSpace(req.URL.Query().Get("api_key"))
}

func callerTokenID(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return "caller:" + hex.EncodeToString(sum[:8])
}

func (r *Resolver) ensureManagedToken(ctx context.Context, a *RequestAuth) error {
	// The store is the source of truth for a token's age: the pool hands out
	// snapshots, and a snapshot taken before the last refresh would make the
	// account look newer (or older) than it is.
	if fresh, ok := r.Store.FindAccount(a.AccountID); ok {
		a.Account = fresh
	}
	token := strings.TrimSpace(a.Account.Token)
	if token == "" {
		return r.refreshAccountToken(ctx, a, refreshReasonRequest)
	}
	if r.tokenNeedsRefresh(a.Account, false) {
		if err := r.refreshAccountToken(ctx, a, refreshReasonRequest); err != nil {
			// A refresh that just failed transiently must not fail the request:
			// the stored token may still work. Only a terminal refusal (handled
			// inside the refresh) means there is nothing to serve from.
			if IsTerminalLoginError(err) {
				return err
			}
			a.DeepSeekToken = token
			return nil
		}
		return nil
	}
	a.DeepSeekToken = token
	return nil
}
