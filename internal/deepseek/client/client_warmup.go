package client

// Account warm-up
//
// A cold account is expensive the first time it is used: the proxy has to sign
// in, run the device check, fetch the risk tokens and only then start the turn
// the caller is waiting for. The page does the same work at boot, before anyone
// types anything, so this project does it at boot too:
//
//	login (only when there is no token)  ->  /users/current  ->  check_device  ->  hif tokens
//
// /users/current doubles as the health check: it is the cheapest call that
// tells a live session from a dead one (no proof of work, no chat), so a warm-up
// run also refreshes banned/muted bookkeeping before traffic arrives. Unlike a
// probe completion it costs no quota and cannot itself trigger a mute, which is
// why warm-up never sends a message.

import (
	"context"
	"strings"
	"sync"
	"time"

	"ds2api/internal/auth"
	"ds2api/internal/config"
)

// WarmUpAccountStatus is what one account's warm-up produced.
type WarmUpAccountStatus struct {
	AccountID string
	OK        bool
	Message   string
	Muted     bool
}

// WarmUpReport is the summary of one warm-up pass.
type WarmUpReport struct {
	Total    int
	Ready    int
	Failed   int
	Muted    int
	Accounts []WarmUpAccountStatus
}

// WarmUpAll prepares every enabled account for traffic. Accounts are warmed
// concurrently, bounded by maxConcurrency, and one account failing never
// affects another.
func (c *Client) WarmUpAll(ctx context.Context, maxConcurrency int) WarmUpReport {
	report := WarmUpReport{}
	if c == nil || c.Store == nil {
		return report
	}
	accounts := c.Store.Accounts()
	candidates := make([]config.Account, 0, len(accounts))
	for _, acc := range accounts {
		if !acc.IsEnabled() || acc.IsBanned() {
			continue
		}
		candidates = append(candidates, acc)
	}
	report.Total = len(candidates)
	if report.Total == 0 {
		return report
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}
	if maxConcurrency > report.Total {
		maxConcurrency = report.Total
	}

	results := make([]WarmUpAccountStatus, len(candidates))
	slots := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for i, acc := range candidates {
		wg.Add(1)
		go func(index int, acc config.Account) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			results[index] = c.WarmUpAccount(ctx, acc)
		}(i, acc)
	}
	wg.Wait()

	report.Accounts = results
	for _, result := range results {
		switch {
		case result.Muted:
			report.Muted++
		case result.OK:
			report.Ready++
		default:
			report.Failed++
		}
	}
	return report
}

// WarmUpAccount readies one account and reports what happened.
func (c *Client) WarmUpAccount(ctx context.Context, acc config.Account) WarmUpAccountStatus {
	result := WarmUpAccountStatus{AccountID: acc.Identifier()}
	if strings.TrimSpace(acc.Identifier()) == "" {
		result.Message = "account has no email or mobile"
		return result
	}

	a := &auth.RequestAuth{
		UseConfigToken: true,
		AccountID:      acc.Identifier(),
		Account:        acc,
		TriedAccounts:  map[string]bool{},
	}
	// 1. A token: reuse the stored one, or sign in with the password.
	if strings.TrimSpace(acc.Token) == "" {
		token, err := c.Login(ctx, acc)
		if err != nil {
			result.Message = "login: " + err.Error()
			return result
		}
		a.DeepSeekToken = token
		a.Account.Token = token
		if c.Store != nil {
			if err := c.Store.UpdateAccountToken(a.AccountID, token); err != nil {
				config.Logger.Warn("[warm_up] persisting login token failed", "account", a.AccountID, "error", err)
			}
		}
	} else {
		a.DeepSeekToken = strings.TrimSpace(acc.Token)
	}

	// 2. Health: /users/current is the cheapest live-session check.
	user, err := c.CurrentUser(ctx, a)
	if err != nil {
		result.Message = "current user: " + err.Error()
		return result
	}
	if user.IsMuted {
		result.Muted = true
		result.Message = "muted"
		c.persistMutedUntil(a.AccountID, user.MuteUntil)
	}

	// 3. Device check (the page runs it right after sign-in) and the risk
	//    tokens the first completion will want.
	if _, err := c.CheckDevice(ctx, a); err != nil {
		config.Logger.Debug("[warm_up] check_device failed", "account", a.AccountID, "error", err)
	}
	c.WarmUpHIF(ctx, a)

	result.OK = true
	if result.Message == "" {
		result.Message = "ready"
	}
	return result
}

// WarmUpOnStartup runs one warm-up pass in the background when the runtime
// allows it. It never blocks server start-up and never fails the boot.
func (c *Client) WarmUpOnStartup() {
	if c == nil || c.Store == nil || !c.Store.RuntimeWarmUpOnStartup() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		started := time.Now()
		report := c.WarmUpAll(ctx, 4)
		if report.Total == 0 {
			return
		}
		config.Logger.Info("[warm_up] accounts warmed",
			"total", report.Total,
			"ready", report.Ready,
			"failed", report.Failed,
			"muted", report.Muted,
			"elapsed_ms", time.Since(started).Milliseconds(),
		)
		for _, acc := range report.Accounts {
			if acc.OK {
				continue
			}
			config.Logger.Warn("[warm_up] account not ready", "account", acc.AccountID, "message", acc.Message)
		}
	}()
}
