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
	email := strings.TrimSpace(user.Email)
	mobile := config.NormalizeMobileForStorage(user.Mobile)
	if email == "" && mobile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "令牌对应的账号没有邮箱或手机号，无法作为账号标识"})
		return
	}

	created := false
	updated := false
	err = h.Store.Update(func(c *config.Config) error {
		for i := range c.Accounts {
			matches := (email != "" && strings.EqualFold(strings.TrimSpace(c.Accounts[i].Email), email)) ||
				(mobile != "" && config.CanonicalMobileKey(c.Accounts[i].Mobile) == config.CanonicalMobileKey(mobile))
			if !matches {
				continue
			}
			if c.Accounts[i].Email == "" && email != "" {
				c.Accounts[i].Email = email
			}
			if c.Accounts[i].Mobile == "" && mobile != "" {
				c.Accounts[i].Mobile = mobile
			}
			c.Accounts[i].Token = token
			// The token was just validated against /users/current, so its age is
			// known: record it, or the sweeper would treat it as unaged.
			c.Accounts[i].TokenRefreshedAt = float64(time.Now().Unix())
			c.Accounts[i].RefreshFailures = 0
			c.Accounts[i].RefreshError = ""
			c.Accounts[i].RefreshRetryAt = 0
			// A fresh, live token clears the suspended marker a previous
			// USER_IS_BANNED left behind.
			if c.Accounts[i].Banned {
				c.Accounts[i].Banned = false
				c.Accounts[i].Disabled = false
				c.Accounts[i].DisabledReason = ""
			}
			if name != "" {
				c.Accounts[i].Name = name
			}
			if remark != "" {
				c.Accounts[i].Remark = remark
			}
			updated = true
			return nil
		}
		c.Accounts = append(c.Accounts, config.Account{
			Name:   name,
			Remark: remark,
			Email:  email,
			Mobile: mobile,
			Token:  token,
			Locale: locale,
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
	identifier := email
	if identifier == "" {
		identifier = mobile
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"identifier": identifier,
		"email":      email,
		"mobile":     mobile,
		"created":    created,
		"updated":    updated,
		"user_id":    user.ID,
		"muted":      user.IsMuted,
		"mute_until": user.MuteUntil,
	})
}
