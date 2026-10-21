package client

// Account identity calls: the current user (the cheapest way to tell a live
// token from a dead one) and the device check the page runs right after a
// successful sign-in.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"ds2api/internal/auth"
	"ds2api/internal/config"
	dsprotocol "ds2api/internal/deepseek/protocol"
)

// CurrentUser is the subset of /api/v0/users/current this project uses.
type CurrentUser struct {
	ID        string
	Email     string
	Mobile    string
	Token     string
	IsMuted   bool
	MuteUntil float64
}

// CurrentUser asks the web app's own account endpoint who a token belongs to.
//
// It is the cheapest live-session check the page offers: a GET with no proof of
// work and no session, and DeepSeek reports a dead token INSIDE the envelope
// (HTTP 200, code 40002 "Missing Token") rather than with a 401 — which is why
// the business code decides validity here, not the status line.
func (c *Client) CurrentUser(ctx context.Context, a *auth.RequestAuth) (*CurrentUser, error) {
	if a == nil {
		return nil, &RequestFailure{Op: "current user", Kind: FailureDirectUnauthorized, Message: "missing token"}
	}
	clients := c.requestClientsForAuth(ctx, a)
	headers := c.authHeadersForAuth(a)
	return c.fetchCurrentUser(ctx, clients.regular, headers)
}

// ValidateToken checks a bare token with a caller-supplied locale. It is what
// token import uses: no account record exists yet, so the request is built from
// the protocol defaults.
func (c *Client) ValidateToken(ctx context.Context, token, locale string) (*CurrentUser, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, &RequestFailure{Op: "current user", Kind: FailureDirectUnauthorized, Message: "missing token"}
	}
	headers := c.authHeaders(token, locale)
	return c.fetchCurrentUser(ctx, c.defaultRequestClients().regular, headers)
}

func (c *Client) fetchCurrentUser(ctx context.Context, doer interface {
	Do(*http.Request) (*http.Response, error)
}, headers map[string]string) (*CurrentUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dsprotocol.DeepSeekCurrentUserURL, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range c.jsonHeaders(headers) {
		req.Header.Set(key, value)
	}
	resp, err := doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			config.Logger.Debug("[current_user] response body close failed", "error", closeErr)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, &RequestFailure{Op: "current user", Kind: FailureManagedUnauthorized, Message: "the sign-in was refused"}
	}
	parsed := map[string]any{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, &RequestFailure{Op: "current user", Kind: FailureUnknown, Message: "unexpected answer: " + previewHIFBody(body)}
	}
	code, bizCode, msg, bizMsg := extractResponseStatus(parsed)
	if code != 0 || bizCode != 0 {
		return nil, &RequestFailure{Op: "current user", Kind: FailureManagedUnauthorized, Message: failureMessage(msg, bizMsg, "token is not a live session")}
	}
	data, _ := parsed["data"].(map[string]any)
	bizData, _ := data["biz_data"].(map[string]any)
	user := bizData
	if nested, ok := bizData["user"].(map[string]any); ok {
		user = nested
	}
	if user == nil {
		return nil, &RequestFailure{Op: "current user", Kind: FailureUnknown, Message: "current user answer carried no user"}
	}
	out := &CurrentUser{
		ID:     firstNonEmptyString(user, "id", "user_id"),
		Email:  firstNonEmptyString(user, "email"),
		Mobile: firstNonEmptyString(user, "mobile_number", "mobile"),
		Token:  firstNonEmptyString(user, "token"),
	}
	if chat, ok := user["chat"].(map[string]any); ok && chat != nil {
		if muted, _ := chat["is_muted"].(float64); muted == 1 {
			out.IsMuted = true
			out.MuteUntil, _ = chat["mute_until"].(float64)
		}
	}
	if out.ID == "" && out.Email == "" && out.Mobile == "" {
		return nil, &RequestFailure{Op: "current user", Kind: FailureUnknown, Message: "current user answer carried no identity"}
	}
	return out, nil
}

// CheckDeviceResult mirrors POST /users/auth_token/check_device.
type CheckDeviceResult struct {
	// Rotate is whatever the server asked us to rotate (null when it did not).
	Rotate any
}

// CheckDevice runs the device check the page issues immediately after a
// successful sign-in. `rotate` being non-null means the server wants the token
// rotated; the value is kept verbatim for the caller to act on (both a bare
// string and an object carrying `token` have been observed).
func (c *Client) CheckDevice(ctx context.Context, a *auth.RequestAuth) (*CheckDeviceResult, error) {
	if a == nil {
		return nil, &RequestFailure{Op: "check device", Kind: FailureDirectUnauthorized, Message: "missing token"}
	}
	clients := c.requestClientsForAuth(ctx, a)
	headers := c.authHeadersForAuth(a)
	payload := map[string]any{
		"device_id":    strings.TrimSpace(a.Account.DeviceID),
		"device_model": "",
	}
	resp, status, err := c.postJSONWithStatus(ctx, clients.regular, clients.fallback, dsprotocol.DeepSeekCheckDeviceURL, headers, payload)
	if err != nil {
		return nil, err
	}
	code, bizCode, msg, bizMsg := extractResponseStatus(resp)
	if status != http.StatusOK || code != 0 || bizCode != 0 {
		return nil, &RequestFailure{Op: "check device", Kind: FailureUnknown, Message: failureMessage(msg, bizMsg, "device check failed")}
	}
	data, _ := resp["data"].(map[string]any)
	bizData, _ := data["biz_data"].(map[string]any)
	if bizData == nil {
		return &CheckDeviceResult{}, nil
	}
	return &CheckDeviceResult{Rotate: bizData["rotate"]}, nil
}
