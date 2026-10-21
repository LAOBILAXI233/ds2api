package accounts

// Importing an account from a pasted session token
//
// A browser that is already signed in to chat.deepseek.com holds a long-lived
// `userToken`; pasting it is the fastest way to add an account (and the only
// way when the password is not at hand, or when a password sign-in keeps
// tripping risk control). The token is never trusted blindly: /users/current
// answers who it belongs to — the cheapest live-session call, no proof of work
// and no chat — and the account is filed under the email or mobile it reports.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"ds2api/internal/config"
	dsclient "ds2api/internal/deepseek/client"
	adminshared "ds2api/internal/httpapi/admin/shared"
)

// tokenValidator is the slice of the DeepSeek client token import needs. It is
// declared here rather than added to the shared interface so existing fakes and
// stubs keep compiling.
type tokenValidator interface {
	ValidateToken(ctx context.Context, token, locale string) (*dsclient.CurrentUser, error)
}

func (h *Handler) importAccountToken(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	_ = json.NewDecoder(r.Body).Decode(&req)
	token := strings.TrimSpace(adminshared.FieldString(req, "token"))
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "需要 token"})
		return
	}
	validator, ok := h.DS.(tokenValidator)
	if !ok || validator == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"detail": "当前运行环境不支持令牌导入"})
		return
	}

	locale := strings.TrimSpace(adminshared.FieldString(req, "locale"))
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	user, err := validator.ValidateToken(ctx, token, locale)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"detail": "DeepSeek 拒绝了这个令牌：" + err.Error(),
			"hint":   "请从已登录 chat.deepseek.com 的标签页执行 JSON.parse(localStorage.getItem(\"userToken\")).value 重新复制",
		})
		return
	}

	name := strings.TrimSpace(adminshared.FieldString(req, "name"))
	remark := strings.TrimSpace(adminshared.FieldString(req, "remark"))
	// Upstream masks the address it reports back ("ryona******@example.com"), so
	// a masked value is never stored as the account's email/mobile: it would
	// become an identifier nobody can type, and it could never match the real
	// account on a re-import. The stable plaintext identity is the user id.
	email := strings.TrimSpace(user.Email)
	mobile := config.NormalizeMobileForStorage(user.Mobile)
	if config.IsMaskedIdentifier(email) {
		email = ""
	}
	if config.IsMaskedIdentifier(mobile) {
		mobile = ""
	}
	userID := strings.TrimSpace(user.ID)
	// `identifier` lets the console say which existing account this token belongs
	// to — the workflow that matters when password sign-in is refused: pick the
	// dead account, paste a token, done. Without it there is nothing to match on
	// (a masked email matches nothing) and the import would add a duplicate.
	target := strings.TrimSpace(adminshared.FieldString(req, "identifier"))
	if email == "" && mobile == "" && userID == "" && target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"detail": "令牌对应的账号没有可用的邮箱、手机号或账号 id，无法作为账号标识",
		})
		return
	}

	created := false
	updated := false
	err = h.Store.Update(func(c *config.Config) error {
		for i := range c.Accounts {
			acc := &c.Accounts[i]
			matches := (target != "" && acc.Identifier() == target) ||
				(userID != "" && strings.TrimSpace(acc.UserID) == userID) ||
				(email != "" && strings.EqualFold(strings.TrimSpace(acc.Email), email)) ||
				(mobile != "" && config.CanonicalMobileKey(acc.Mobile) == config.CanonicalMobileKey(mobile))
			if !matches {
				continue
			}
			if acc.UserID == "" && userID != "" {
				acc.UserID = userID
			}
			if acc.Email == "" && email != "" {
				acc.Email = email
			}
			if acc.Mobile == "" && mobile != "" {
				acc.Mobile = mobile
			}
			acc.Token = token
			// The token was just validated against /users/current, so its age is
			// known: record it, or the sweeper would treat it as unaged.
			acc.TokenRefreshedAt = float64(time.Now().Unix())
			acc.RefreshFailures = 0
			acc.RefreshError = ""
			acc.RefreshRetryAt = 0
			// A live token clears every "this account cannot be used" marker a
			// refused password sign-in left behind — including the local
			// cooldown, which otherwise keeps the pool skipping the account even
			// though its token is fine.
			acc.CooldownUntil = 0
			acc.Banned = false
			acc.Disabled = false
			acc.DisabledReason = ""
			if name != "" {
				acc.Name = name
			}
			if remark != "" {
				acc.Remark = remark
			}
			updated = true
			return nil
		}
		c.Accounts = append(c.Accounts, config.Account{
			Name:             name,
			Remark:           remark,
			UserID:           userID,
			Email:            email,
			Mobile:           mobile,
			Token:            token,
			TokenRefreshedAt: float64(time.Now().Unix()),
			Locale:           locale,
		})
		created = true
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": err.Error()})
		return
	}

	if h.Pool != nil {
		h.Pool.Reset()
	}
	// Report the identifier the account actually ends up with, not the one we
	// derived: a masked-email import becomes `user:<id>`, and the console has to
	// show something the operator can then use in other admin calls.
	identifier := email
	if identifier == "" {
		identifier = mobile
	}
	if identifier == "" && userID != "" {
		identifier = "user:" + userID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"identifier":      identifier,
		"email":           email,
		"mobile":          mobile,
		"created":         created,
		"updated":         updated,
		"user_id":         userID,
		"masked_identity": config.IsMaskedIdentifier(user.Email) || config.IsMaskedIdentifier(user.Mobile),
		"muted":           user.IsMuted,
		"mute_until":      user.MuteUntil,
	})
}
