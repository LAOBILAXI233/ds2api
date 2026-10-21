package client

import (
	"context"
	dsprotocol "ds2api/internal/deepseek/protocol"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"ds2api/internal/account"
	"ds2api/internal/auth"
	"ds2api/internal/config"
)

func (c *Client) Login(ctx context.Context, acc config.Account) (string, error) {
	deviceID, err := c.ensureAccountDeviceID(acc)
	if err != nil {
		return "", err
	}
	acc.DeviceID = deviceID
	// Start the new session with a clean jar: replaying cookies issued against
	// the previous token alongside a freshly minted one is incoherent.
	c.cookies.forget(acc.Identifier())
	clients := c.requestClientsForAccount(acc)
	payload := map[string]any{
		"email":     "",
		"mobile":    "",
		"password":  strings.TrimSpace(acc.Password),
		"area_code": "",
		"device_id": deviceID,
		"os":        "web",
	}
	if email := strings.TrimSpace(acc.Email); email != "" {
		payload["email"] = email
	} else if mobile := strings.TrimSpace(acc.Mobile); mobile != "" {
		loginMobile, areaCode := normalizeMobileForLogin(mobile)
		payload["mobile"] = loginMobile
		payload["area_code"] = areaCode
	} else {
		return "", errors.New("missing email/mobile")
	}
	loginHeaders := dsprotocol.LoginHeaders(acc.Locale)
	// The page signs in from /sign_in, and a login POST whose Referer is the
	// site root describes a request the browser never makes.
	loginHeaders["Referer"] = dsprotocol.DeepSeekSignInReferer
	loginHeaders["Origin"] = "https://chat.deepseek.com"
	// The sign-in request carries the same device identity its payload does.
	applyDeviceHeaders(loginHeaders, deviceID)
	resp, err := c.postJSON(ctx, clients.regular, clients.fallback, dsprotocol.DeepSeekLoginURL, loginHeaders, payload)
	if err != nil {
		return "", err
	}
	code := intFrom(resp["code"])
	if code != 0 {
		// A top-level code is the envelope's, not the business refusal's: it is
		// classified so the refresh policy can tell "try again" from "never
		// again".
		return "", classifyLoginRefusal(code, asResponseMessage(resp["msg"]))
	}
	data, _ := resp["data"].(map[string]any)
	bizCode := intFrom(data["biz_code"])
	bizMsg, _ := data["biz_msg"].(string)
	if bizCode != 0 {
		if isUserBannedResponse(bizCode, bizMsg) {
			c.persistBannedAccount(acc.Identifier(), "账户已被停用")
			return "", auth.NewLoginError(auth.LoginCodeBanned, "USER_IS_BANNED")
		}
		if loginErr := classifyLoginRefusal(bizCode, bizMsg); loginErr != nil {
			return "", loginErr
		}
	}
	bizData, _ := data["biz_data"].(map[string]any)
	user, _ := bizData["user"].(map[string]any)
	token, _ := user["token"].(string)
	if strings.TrimSpace(token) == "" {
		return "", auth.NewLoginError(0, "the sign-in answered without a token")
	}
	if chat, _ := user["chat"].(map[string]any); chat != nil {
		if isMuted, _ := chat["is_muted"].(float64); isMuted == 1 {
			muteUntil, _ := chat["mute_until"].(float64)
			c.persistMutedUntil(acc.Identifier(), muteUntil)
			config.Logger.Warn("[login] account is muted", "account", acc.Identifier(), "mute_until", muteUntil)
		}
	}
	if acc.Banned {
		c.clearBannedAccount(acc.Identifier())
	}
	ssoID, _ := user["id"].(string)
	loginAuth := &auth.RequestAuth{
		UseConfigToken: true,
		DeepSeekToken:  token,
		AccountID:      acc.Identifier(),
		Account:        acc,
	}
	auth.WithAuth(ctx, loginAuth)
	// The page's post-sign-in sequence: device check, client settings, then the
	// training switch. The device check is what the server uses to decide
	// whether this device may keep the token, so it runs before traffic does.
	c.checkDeviceAfterLogin(ctx, loginAuth)
	c.reportClientSettingsAfterLogin(ctx, loginAuth, ssoID)
	if err := c.DisableTrainingAllowed(ctx, loginAuth); err != nil {
		config.Logger.Warn("[disable_training] failed after login", "account", acc.Identifier(), "error", err)
	}
	// Prefetch the risk tokens in the background: a sign-in already cost a
	// round trip, and the first completion should not wait on two more
	// requests (the page starts its pollers as soon as it boots).
	c.scheduleHIFRefresh(ctx, loginAuth, strings.TrimSpace(loginAuth.Account.DeviceID))
	return token, nil
}

// checkDeviceAfterLogin runs POST /users/auth_token/check_device. A non-null
// `rotate` means the server asked for a token rotation; the shape has been seen
// both as a bare string and as an object carrying `token`, so both are adopted
// when they parse, and anything else is logged for inspection.
func (c *Client) checkDeviceAfterLogin(ctx context.Context, a *auth.RequestAuth) {
	if a == nil || strings.TrimSpace(a.Account.DeviceID) == "" {
		return
	}
	result, err := c.CheckDevice(ctx, a)
	if err != nil {
		config.Logger.Debug("[check_device] failed after login", "account", a.AccountID, "error", err)
		return
	}
	if result == nil || result.Rotate == nil {
		return
	}
	if token := rotateTokenValue(result.Rotate); token != "" {
		if c.Store != nil && strings.TrimSpace(a.AccountID) != "" {
			if rerr := c.Store.UpdateAccountToken(a.AccountID, token); rerr != nil {
				config.Logger.Warn("[check_device] persisting rotated token failed", "account", a.AccountID, "error", rerr)
				return
			}
		}
		a.DeepSeekToken = token
		a.Account.Token = token
		config.Logger.Info("[check_device] token rotated as instructed by upstream", "account", a.AccountID)
		return
	}
	config.Logger.Info("[check_device] upstream asked for rotation in an unknown shape", "account", a.AccountID, "rotate", fmt.Sprint(result.Rotate))
}

// rotateTokenValue pulls a token out of the rotate instruction, if it carries
// one in a shape this project recognises.
func rotateTokenValue(rotate any) string {
	switch v := rotate.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		for _, key := range []string{"token", "new_token", "access_token"} {
			if token, _ := v[key].(string); strings.TrimSpace(token) != "" {
				return strings.TrimSpace(token)
			}
		}
	}
	return ""
}

func (c *Client) ensureAccountDeviceID(acc config.Account) (string, error) {
	deviceID := strings.TrimSpace(acc.DeviceID)
	if deviceID != "" {
		return deviceID, nil
	}
	deviceID, err := createRandomDeviceID()
	if err != nil {
		return "", err
	}
	if c == nil || c.Store == nil {
		return deviceID, nil
	}
	identifier := acc.Identifier()
	if identifier == "" {
		return deviceID, nil
	}
	if err := c.Store.Update(func(cfg *config.Config) error {
		for i := range cfg.Accounts {
			if cfg.Accounts[i].Identifier() == identifier {
				cfg.Accounts[i].DeviceID = deviceID
				return nil
			}
		}
		return errors.New("account not found")
	}); err != nil {
		return "", err
	}
	return deviceID, nil
}

// createRandomDeviceID mints the device identity a new account presents: the
// same value goes into the login payload's device_id and into X-Device-Id on
// every request that carries one. The browser's device identity is a UUID, and
// a 36-character UUID-shaped value is what the real client sends, so new
// accounts get one. Values already stored on existing accounts are left alone:
// silently re-keying a working account's device is exactly the kind of change
// that makes upstream re-verify it.
func createRandomDeviceID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (c *Client) reportClientSettingsAfterLogin(ctx context.Context, a *auth.RequestAuth, ssoID string) {
	if c == nil || a == nil || strings.TrimSpace(a.DeepSeekToken) == "" || strings.TrimSpace(a.Account.DeviceID) == "" {
		return
	}
	if err := c.ReportClientSettings(ctx, a, ssoID); err != nil {
		config.Logger.Warn("[client_settings] report after login failed", "account", a.AccountID, "error", err)
	}
}

// persistMutedUntil 持久化账号禁言到期时间到配置。
// muteUntil 为 DeepSeek 返回的 Unix 时间戳（秒，可能含小数）。
// 当弹性号池开启时，在同一个事务内触发 ReconcileElasticPool 补位。
func (c *Client) persistMutedUntil(identifier string, muteUntil float64) {
	if c == nil || c.Store == nil || strings.TrimSpace(identifier) == "" || muteUntil <= 0 {
		return
	}
	if err := c.Store.Update(func(cfg *config.Config) error {
		for i := range cfg.Accounts {
			if cfg.Accounts[i].Identifier() != identifier {
				continue
			}
			cfg.Accounts[i].MutedUntil = muteUntil
			break
		}
		if cfg.ElasticPool.Enabled {
			account.ReconcileElasticPool(cfg)
		}
		return nil
	}); err != nil {
		config.Logger.Error("[muted_account] failed to persist muted_until", "account", identifier, "error", err)
	}
}

// isUserBannedResponse 判断登录响应是否表示账号被上游停用（USER_IS_BANNED）。
func isUserBannedResponse(bizCode int, bizMsg string) bool {
	msg := strings.ToLower(strings.TrimSpace(bizMsg))
	return strings.Contains(msg, "user_is_banned") || bizCode == 10
}

// persistBannedAccount 持久化账号因上游 USER_IS_BANNED 而被停用的状态。
// 与禁言不同：禁言有 MutedUntil 可自动恢复，而被上游停用需等待
// 下次成功刷新 token 后才会解除。
func (c *Client) persistBannedAccount(identifier string, reason string) {
	if c == nil || c.Store == nil || strings.TrimSpace(identifier) == "" || strings.TrimSpace(reason) == "" {
		return
	}
	if err := c.Store.Update(func(cfg *config.Config) error {
		for i := range cfg.Accounts {
			if cfg.Accounts[i].Identifier() != identifier {
				continue
			}
			cfg.Accounts[i].Banned = true
			cfg.Accounts[i].Disabled = true
			cfg.Accounts[i].DisabledReason = reason
			break
		}
		if cfg.ElasticPool.Enabled {
			account.ReconcileElasticPool(cfg)
		}
		return nil
	}); err != nil {
		config.Logger.Error("[banned_account] failed to persist banned state", "account", identifier, "error", err)
		return
	}
	if c.Auth != nil && c.Auth.Pool != nil {
		c.Auth.Pool.Reset()
	}
	config.Logger.Warn("[banned_account] account disabled after USER_IS_BANNED", "account", identifier, "reason", reason)
}

// clearBannedAccount 在成功刷新 token 后解除上游停用状态。
func (c *Client) clearBannedAccount(identifier string) {
	if c == nil || c.Store == nil || strings.TrimSpace(identifier) == "" {
		return
	}
	if err := c.Store.Update(func(cfg *config.Config) error {
		for i := range cfg.Accounts {
			if cfg.Accounts[i].Identifier() != identifier {
				continue
			}
			if !cfg.Accounts[i].Banned {
				return nil
			}
			cfg.Accounts[i].Banned = false
			cfg.Accounts[i].Disabled = false
			cfg.Accounts[i].DisabledReason = ""
			break
		}
		if cfg.ElasticPool.Enabled {
			account.ReconcileElasticPool(cfg)
		}
		return nil
	}); err != nil {
		config.Logger.Error("[banned_account] failed to clear banned state", "account", identifier, "error", err)
		return
	}
	if c.Auth != nil && c.Auth.Pool != nil {
		c.Auth.Pool.Reset()
	}
	config.Logger.Info("[banned_account] account re-enabled after successful token refresh", "account", identifier)
}

// captchaCooldown is how long an account is benched after a captcha challenge.
// A challenge means risk control has already flagged this account; continuing
// to drive traffic through it is the fastest way to escalate to a mute.
// Override with DS2API_CAPTCHA_COOLDOWN_MINUTES.
const defaultCaptchaCooldownMinutes = 30

func captchaCooldownDuration() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("DS2API_CAPTCHA_COOLDOWN_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return defaultCaptchaCooldownMinutes * time.Minute
}

// coolDownAfterCaptcha benches the account and reports whether it was applied.
func (c *Client) coolDownAfterCaptcha(a *auth.RequestAuth, op string) {
	if c == nil || a == nil || !a.UseConfigToken {
		return
	}
	identifier := strings.TrimSpace(a.AccountID)
	if identifier == "" {
		return
	}
	cooldown := captchaCooldownDuration()
	if cooldown <= 0 {
		return
	}
	until := float64(time.Now().Add(cooldown).Unix())
	c.persistCooldownUntil(identifier, until)
	a.Account.CooldownUntil = until
	config.Logger.Warn("[captcha] account cooled down after challenge",
		"op", op, "account", identifier, "cooldown_minutes", int(cooldown.Minutes()), "until", until)
}

// persistCooldownUntil stores the cooldown deadline, mirroring how a mute is
// persisted so an elastic pool can promote a standby account in its place.
func (c *Client) persistCooldownUntil(identifier string, until float64) {
	if c == nil || c.Store == nil || strings.TrimSpace(identifier) == "" || until <= 0 {
		return
	}
	if err := c.Store.Update(func(cfg *config.Config) error {
		for i := range cfg.Accounts {
			if cfg.Accounts[i].Identifier() != identifier {
				continue
			}
			cfg.Accounts[i].CooldownUntil = until
			break
		}
		if cfg.ElasticPool.Enabled {
			account.ReconcileElasticPool(cfg)
		}
		return nil
	}); err != nil {
		config.Logger.Error("[captcha] failed to persist cooldown_until", "account", identifier, "error", err)
	}
}

func (c *Client) CreateSession(ctx context.Context, a *auth.RequestAuth, maxAttempts int) (string, error) {
	if maxAttempts <= 0 {
		maxAttempts = c.maxRetries
	}
	clients := c.requestClientsForAuth(ctx, a)
	attempts := 0
	refreshed := false
	for attempts < maxAttempts {
		headers := c.authHeadersForAuth(a)
		resp, status, err := c.postJSONWithStatus(ctx, clients.regular, clients.fallback, dsprotocol.DeepSeekCreateSessionURL, headers, map[string]any{})
		if err != nil {
			config.Logger.Warn("[create_session] request error", "error", err, "account", a.AccountID)
			attempts++
			continue
		}
		code, bizCode, msg, bizMsg := extractResponseStatus(resp)
		if status == http.StatusOK && code == 0 && bizCode == 0 {
			sessionID := extractCreateSessionID(resp)
			if sessionID != "" {
				return sessionID, nil
			}
		}
		if ch := DetectCaptchaChallenge(resp); ch != nil {
			config.Logger.Warn("[create_session] captcha challenge detected", "account", a.AccountID, "instruction", ch.Instruction, "image_url", ch.ImageURL, "rid", ch.Rid)
			c.coolDownAfterCaptcha(a, "create_session")
			if a.UseConfigToken && c.Auth.SwitchAccount(ctx, a) {
				refreshed = false
				attempts++
				continue
			}
			return "", &RequestFailure{Op: "create session", Kind: FailureCaptchaRequired, Message: failureMessage(msg, bizMsg, "captcha challenge required")}
		}
		config.Logger.Warn("[create_session] failed", "status", status, "code", code, "biz_code", bizCode, "msg", msg, "biz_msg", bizMsg, "use_config_token", a.UseConfigToken, "account", a.AccountID)
		if a.UseConfigToken {
			if !refreshed && shouldAttemptRefresh(status, code, bizCode, msg, bizMsg) {
				if c.Auth.RefreshToken(ctx, a) {
					refreshed = true
					continue
				}
			}
			if c.Auth.SwitchAccount(ctx, a) {
				refreshed = false
				attempts++
				continue
			}
		}
		attempts++
	}
	return "", errors.New("create session failed")
}

func (c *Client) GetPow(ctx context.Context, a *auth.RequestAuth, maxAttempts int) (string, error) {
	return c.GetPowForTarget(ctx, a, dsprotocol.DeepSeekCompletionTargetPath, maxAttempts)
}

func (c *Client) GetPowForTarget(ctx context.Context, a *auth.RequestAuth, targetPath string, maxAttempts int) (string, error) {
	if maxAttempts <= 0 {
		maxAttempts = c.maxRetries
	}
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" {
		targetPath = dsprotocol.DeepSeekCompletionTargetPath
	}
	clients := c.requestClientsForAuth(ctx, a)
	attempts := 0
	refreshed := false
	lastFailureKind := FailureUnknown
	lastFailureMessage := ""
	for attempts < maxAttempts {
		headers := c.authHeadersForAuth(a)
		resp, status, err := c.postJSONWithStatus(ctx, clients.regular, clients.fallback, dsprotocol.DeepSeekCreatePowURL, headers, map[string]any{"target_path": targetPath})
		if err != nil {
			config.Logger.Warn("[get_pow] request error", "error", err, "account", a.AccountID, "target_path", targetPath)
			lastFailureKind = FailureUnknown
			lastFailureMessage = err.Error()
			attempts++
			continue
		}
		code, bizCode, msg, bizMsg := extractResponseStatus(resp)
		if status == http.StatusOK && code == 0 && bizCode == 0 {
			data, _ := resp["data"].(map[string]any)
			bizData, _ := data["biz_data"].(map[string]any)
			challenge, _ := bizData["challenge"].(map[string]any)
			answer, err := ComputePow(ctx, challenge)
			if err != nil {
				attempts++
				continue
			}
			return BuildPowHeader(challenge, answer)
		}
		if ch := DetectCaptchaChallenge(resp); ch != nil {
			config.Logger.Warn("[get_pow] captcha challenge detected", "account", a.AccountID, "target_path", targetPath, "instruction", ch.Instruction, "image_url", ch.ImageURL, "rid", ch.Rid)
			c.coolDownAfterCaptcha(a, "get_pow")
			lastFailureKind = FailureCaptchaRequired
			lastFailureMessage = failureMessage(msg, bizMsg, "captcha challenge required")
			if a.UseConfigToken && c.Auth.SwitchAccount(ctx, a) {
				refreshed = false
				attempts++
				continue
			}
			attempts++
			continue
		}
		config.Logger.Warn("[get_pow] failed", "status", status, "code", code, "biz_code", bizCode, "msg", msg, "biz_msg", bizMsg, "use_config_token", a.UseConfigToken, "account", a.AccountID, "target_path", targetPath)
		lastFailureMessage = failureMessage(msg, bizMsg, "get pow failed")
		if isTokenInvalid(status, code, bizCode, msg, bizMsg) || isAuthIndicativeBizFailure(msg, bizMsg) {
			lastFailureKind = authFailureKind(a.UseConfigToken)
		} else {
			lastFailureKind = FailureUnknown
		}
		if a.UseConfigToken {
			if !refreshed && shouldAttemptRefresh(status, code, bizCode, msg, bizMsg) {
				if c.Auth.RefreshToken(ctx, a) {
					refreshed = true
					continue
				}
			}
			if c.Auth.SwitchAccount(ctx, a) {
				refreshed = false
				attempts++
				continue
			}
		}
		attempts++
	}
	if lastFailureKind != FailureUnknown {
		return "", &RequestFailure{Op: "get pow", Kind: lastFailureKind, Message: lastFailureMessage}
	}
	return "", errors.New("get pow failed")
}

func (c *Client) authHeaders(token string, locale string) map[string]string {
	headers := dsprotocol.BaseHeadersFor(locale)
	headers["authorization"] = "Bearer " + token
	return headers
}

// authHeadersForAuth is authHeaders with the account's own device identity
// attached. The web client sends X-Device-Id on every API call (and an empty
// X-Device-Model on the web platform), so a request without them is already a
// weaker imitation of the page than one with them. The value is the account's
// stored device id — the same one its login payload carries — so two accounts
// never present themselves as the same device.
func (c *Client) authHeadersForAuth(a *auth.RequestAuth) map[string]string {
	if a == nil {
		return c.authHeaders("", "")
	}
	headers := c.authHeaders(a.DeepSeekToken, a.Account.Locale)
	applyDeviceHeaders(headers, a.Account.DeviceID)
	return headers
}

// applyDeviceHeaders stamps the device identity onto a header set.
func applyDeviceHeaders(headers map[string]string, deviceID string) {
	if headers == nil {
		return
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return
	}
	headers["x-device-id"] = deviceID
	headers["x-device-model"] = ""
}

// localeFromContext 尝试从上下文中提取账号 locale，供只有 token 的直通接口使用。
func localeFromContext(ctx context.Context) string {
	if a, ok := auth.FromContext(ctx); ok {
		return strings.TrimSpace(a.Account.Locale)
	}
	return ""
}

func isTokenInvalid(status int, code int, bizCode int, msg string, bizMsg string) bool {
	msg = strings.ToLower(strings.TrimSpace(msg) + " " + strings.TrimSpace(bizMsg))
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return true
	}
	if code == 40001 || code == 40002 || code == 40003 || bizCode == 40001 || bizCode == 40002 || bizCode == 40003 {
		return true
	}
	return strings.Contains(msg, "token") ||
		strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "expired") ||
		strings.Contains(msg, "not login") ||
		strings.Contains(msg, "login required") ||
		strings.Contains(msg, "invalid jwt")
}

func shouldAttemptRefresh(status int, code int, bizCode int, msg string, bizMsg string) bool {
	if isTokenInvalid(status, code, bizCode, msg, bizMsg) {
		return true
	}
	// Some DeepSeek failures come back as HTTP 200/code=0 but with non-zero biz_code.
	// Only attempt refresh when these biz failures still look auth-related.
	return status == http.StatusOK &&
		code == 0 &&
		bizCode != 0 &&
		isAuthIndicativeBizFailure(msg, bizMsg)
}

func isAuthIndicativeBizFailure(msg string, bizMsg string) bool {
	combined := strings.ToLower(strings.TrimSpace(msg) + " " + strings.TrimSpace(bizMsg))
	authKeywords := []string{
		"auth",
		"authorization",
		"credential",
		"expired",
		"invalid jwt",
		"jwt",
		"login",
		"not login",
		"session expired",
		"token",
		"unauthorized",
		"登录",
		"未登录",
		"认证",
		"凭证",
		"会话过期",
		"令牌",
	}
	for _, keyword := range authKeywords {
		if strings.Contains(combined, keyword) {
			return true
		}
	}
	return false
}

func authFailureKind(useConfigToken bool) FailureKind {
	if useConfigToken {
		return FailureManagedUnauthorized
	}
	return FailureDirectUnauthorized
}

func failureMessage(msg string, bizMsg string, fallback string) string {
	if trimmed := strings.TrimSpace(bizMsg); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(msg); trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(fallback)
}

// DeepSeek has returned create-session ids in both biz_data.id and
// biz_data.chat_session.id across observed response variants; accept either.
func extractCreateSessionID(resp map[string]any) string {
	data, _ := resp["data"].(map[string]any)
	bizData, _ := data["biz_data"].(map[string]any)
	if sessionID, _ := bizData["id"].(string); strings.TrimSpace(sessionID) != "" {
		return strings.TrimSpace(sessionID)
	}
	if chatSession, ok := bizData["chat_session"].(map[string]any); ok {
		if sessionID, _ := chatSession["id"].(string); strings.TrimSpace(sessionID) != "" {
			return strings.TrimSpace(sessionID)
		}
	}
	return ""
}

func extractResponseStatus(resp map[string]any) (code int, bizCode int, msg string, bizMsg string) {
	code = intFrom(resp["code"])
	msg, _ = resp["msg"].(string)
	data, _ := resp["data"].(map[string]any)
	bizCode = intFrom(data["biz_code"])
	bizMsg, _ = data["biz_msg"].(string)
	if strings.TrimSpace(bizMsg) == "" {
		if bizData, ok := data["biz_data"].(map[string]any); ok {
			bizMsg, _ = bizData["msg"].(string)
		}
	}
	return code, bizCode, msg, bizMsg
}

func normalizeMobileForLogin(raw string) (mobile string, areaCode string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	hasPlus := strings.HasPrefix(s, "+")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	digits := b.String()
	if digits == "" {
		return "", ""
	}
	if (hasPlus || strings.HasPrefix(digits, "86")) && strings.HasPrefix(digits, "86") && len(digits) == 13 {
		return digits[2:], "+86"
	}
	return digits, "+86"
}

// classifyLoginRefusal turns an upstream refusal into a LoginError. The codes
// ds-free-api treats as terminal come back terminal; everything else (an unknown
// code, a WAF hiccup, a transient 5xx) is retryable.
func classifyLoginRefusal(code int, message string) *auth.LoginError {
	text := strings.ToLower(strings.TrimSpace(message))
	switch {
	case code == auth.LoginCodeBanned || strings.Contains(text, "user_is_banned"):
		return auth.NewLoginError(auth.LoginCodeBanned, "USER_IS_BANNED")
	case code == auth.LoginCodeMuted || strings.Contains(text, "muted") || strings.Contains(text, "limited") || strings.Contains(text, "禁言"):
		return auth.NewLoginError(auth.LoginCodeMuted, message)
	case code == auth.LoginCodeCredentials || strings.Contains(text, "password") || strings.Contains(text, "密码"):
		return auth.NewLoginError(auth.LoginCodeCredentials, message)
	case code == auth.LoginCodeDevice || strings.Contains(text, "risk_device") || strings.Contains(text, "device") || strings.Contains(text, "设备"):
		return auth.NewLoginError(auth.LoginCodeDevice, message)
	}
	// An unknown code is kept retryable: it is more likely a temporary
	// envelope (WAF, rate limit) than a permanent refusal.
	return &auth.LoginError{Code: code, Message: message}
}

func asResponseMessage(raw any) string {
	if text, ok := raw.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}
