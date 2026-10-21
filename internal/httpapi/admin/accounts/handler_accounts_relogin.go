package accounts

// Manual re-login
//
// The sweeper decides on its own when to refresh; this endpoint is the
// operator's override — ds-free-api's `re_login_single`. It is also the way back
// from an account the refresh policy retired: a manual sign-in clears the
// retirement flag, so a fixed password (or a token upstream accepts again) puts
// the account back in rotation without editing config.json.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"

	"ds2api/internal/auth"
	"ds2api/internal/config"
	adminshared "ds2api/internal/httpapi/admin/shared"
)

// accountTokenRefresher is the slice of the resolver re-login needs, declared
// here rather than added to the shared interfaces so existing fakes keep
// compiling.
type accountTokenRefresher interface {
	RefreshAccountToken(ctx context.Context, acc config.Account, reason string) error
	ClearRefreshBlocked(identifier string) error
}

func (h *Handler) reloginAccount(w http.ResponseWriter, r *http.Request) {
	identifier := chi.URLParam(r, "identifier")
	if decoded, err := url.PathUnescape(identifier); err == nil {
		identifier = decoded
	}
	if identifier == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "缺少账号标识"})
		return
	}
	acc, ok := findAccountByIdentifier(h.Store, identifier)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"detail": "账号不存在"})
		return
	}
	refresher, ok := h.Auth.(accountTokenRefresher)
	if !ok || refresher == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"detail": "当前运行环境不支持重新登录"})
		return
	}
	var req map[string]any
	_ = json.NewDecoder(r.Body).Decode(&req)
	// `clear` (default true) lifts a refresh retirement; `clear=false` only asks
	// for a token and keeps the account's recorded state.
	clear := true
	if v, present := adminshared.FieldBoolOptional(req, "clear"); present {
		clear = v
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := refresher.RefreshAccountToken(ctx, acc, "manual"); err != nil {
		// `risk_cooldown` tells the console that the sign-in circuit breaker — not
		// this account — is what refused, so the UI can say "wait" instead of
		// suggesting the password is wrong.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"detail":        "重新登录失败：" + err.Error(),
			"terminal":      auth.IsTerminalLoginError(err),
			"risk_cooldown": errors.Is(err, auth.ErrRiskCooldown),
			"identifier":    acc.Identifier(),
		})
		return
	}
	if clear {
		if err := refresher.ClearRefreshBlocked(acc.Identifier()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"detail": err.Error()})
			return
		}
	}
	updated, _ := findAccountByIdentifier(h.Store, acc.Identifier())
	writeJSON(w, http.StatusOK, map[string]any{
		"success":          true,
		"identifier":       updated.Identifier(),
		"disabled":         updated.Disabled,
		"disabled_reason":  updated.DisabledReason,
		"banned":           updated.IsBanned(),
		"token_refreshed":  updated.TokenRefreshedAt > 0,
		"refresh_failures": updated.RefreshFailures,
	})
}
