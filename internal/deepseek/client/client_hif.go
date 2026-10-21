package client

// HIF risk-control tokens (x-hif-leim / x-hif-dliq)
//
// The web client keeps two pollers alive for as long as the page is open. Each
// one GETs an unauthenticated endpoint, stores the answer in localStorage
// (`hif_leim_cached` / `hif_dliq_cached`) and hands it back through a header
// provider that stamps BOTH headers onto every SSE request — that is, onto
// /chat/completion, /chat/continue and /chat/resume_stream, the three calls
// that actually start or continue generation.
//
//	GET https://hif-leim.deepseek.com/query  -> {"code":0,...,"biz_data":{"value":"…"}}
//	GET https://hif-dliq.deepseek.com/query  (same envelope, same x-hif-ttl)
//
// Verified against the live endpoint: HTTP 200, `x-hif-ttl: 600`, and the
// envelope above (hif-dliq is IPv6-only behind the vendor's WAF, so it can be
// unreachable on an IPv4-only host — each endpoint is cached and skipped
// independently, as the page's own `value && (out[h] = value)` provider does).
//
// A token is bound to the device that asked for it, so this cache is keyed by
// X-Device-Id and every account contributes its own random device identity (see
// ensureAccountDeviceID). Nothing is shared between accounts, which is the
// property that makes sending these headers no worse than sending none: N
// accounts never look like one device.
//
// A fetch failure never fails the business request — the header is simply left
// off, exactly as the page's provider does when its store is still empty, and
// the endpoint is retried after a backoff.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"ds2api/internal/auth"
	"ds2api/internal/config"
	dsprotocol "ds2api/internal/deepseek/protocol"
)

const (
	HIFLeimURL = "https://hif-leim.deepseek.com/query"
	HIFDliqURL = "https://hif-dliq.deepseek.com/query"

	hifDefaultTTL      = 600 * time.Second
	hifFetchTimeout    = 3 * time.Second
	hifRefreshMargin   = 30 * time.Second
	hifInitialBackoff  = 30 * time.Second
	hifMaxBackoff      = 10 * time.Minute
	hifMaxValueLength  = 4096
	hifErrorBodyWindow = 200
)

type hifKind struct {
	header string
	url    string
	name   string
}

var hifKinds = []hifKind{
	{header: "x-hif-leim", url: HIFLeimURL, name: "leim"},
	{header: "x-hif-dliq", url: HIFDliqURL, name: "dliq"},
}

// hifToken is one endpoint's cache for one device.
type hifToken struct {
	mu          sync.Mutex
	value       string
	expiresAt   time.Time
	nextAttempt time.Time
	failures    int
}

// hifRegistry keeps the per-device token caches and the set of devices with a
// refresh in flight.
type hifRegistry struct {
	mu       sync.Mutex
	tokens   map[string]*hifToken
	inflight map[string]bool
}

func newHIFRegistry() *hifRegistry {
	return &hifRegistry{tokens: map[string]*hifToken{}, inflight: map[string]bool{}}
}

// beginRefresh claims the refresh slot for a device.
func (r *hifRegistry) beginRefresh(deviceID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight == nil {
		r.inflight = map[string]bool{}
	}
	if r.inflight[deviceID] {
		return false
	}
	r.inflight[deviceID] = true
	return true
}

func (r *hifRegistry) endRefresh(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.inflight, deviceID)
}

func (r *hifRegistry) token(deviceID, kind string) *hifToken {
	key := kind + "|" + deviceID
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tokens == nil {
		r.tokens = map[string]*hifToken{}
	}
	if existing, ok := r.tokens[key]; ok {
		return existing
	}
	token := &hifToken{}
	r.tokens[key] = token
	return token
}

// hifTokensEnabled reports whether the tokens are attached at all. Default on:
// a request that carries the same headers as the page is the whole point, and a
// failed fetch degrades to "no header" rather than to an error. Set
// DS2API_HIF_TOKENS=0 or runtime.hif_tokens=false to compare behaviour without.
func (c *Client) hifTokensEnabled() bool {
	if raw := strings.TrimSpace(strings.ToLower(os.Getenv("DS2API_HIF_TOKENS"))); raw != "" {
		switch raw {
		case "0", "false", "no", "off":
			return false
		default:
			return true
		}
	}
	if c == nil || c.Store == nil {
		return true
	}
	return c.Store.RuntimeHIFTokensEnabled()
}

func hifFailureBackoff(failures int) time.Duration {
	if failures <= 1 {
		return hifInitialBackoff
	}
	exp := failures - 1
	if exp > 10 {
		exp = 10
	}
	backoff := hifInitialBackoff << exp
	if backoff > hifMaxBackoff || backoff <= 0 {
		return hifMaxBackoff
	}
	return backoff
}

// hifHeaders returns the tokens that are already cached for this account's
// device. A miss never blocks the caller: the fetch is scheduled in the
// background and this request simply goes out without the header, the way the
// page behaves while its poller is still empty. Keeping the request path free
// of network waits is what preserves the gateway's time-to-first-token.
func (c *Client) hifHeaders(ctx context.Context, a *auth.RequestAuth) map[string]string {
	if c == nil || c.hif == nil || a == nil || !c.hifTokensEnabled() {
		return nil
	}
	deviceID := accountDeviceID(a)
	if deviceID == "" {
		return nil
	}
	headers := map[string]string{}
	missed := false
	for _, kind := range hifKinds {
		value, fresh := c.peekHIFToken(deviceID, kind)
		if value == "" || !fresh {
			missed = true
		}
		if value != "" {
			headers[kind.header] = value
		}
	}
	if missed {
		c.scheduleHIFRefresh(ctx, a, deviceID)
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// peekHIFToken returns the cached value and whether it is still inside its TTL.
// A stale value is still handed out (like the page's localStorage entry) but
// marks the cache for a refresh.
func (c *Client) peekHIFToken(deviceID string, kind hifKind) (string, bool) {
	token := c.hif.token(deviceID, kind.name)
	token.mu.Lock()
	defer token.mu.Unlock()
	if token.value == "" {
		return "", false
	}
	now := time.Now()
	if token.expiresAt.After(now) {
		return token.value, true
	}
	// A stale value is reused while a refresh is in flight (the page keeps
	// handing out its localStorage copy), but not forever: a token that is a
	// whole lifetime past its TTL is more likely to look wrong than to help.
	if now.Sub(token.expiresAt) < hifDefaultTTL {
		return token.value, false
	}
	return "", false
}

func accountDeviceID(a *auth.RequestAuth) string {
	if a == nil {
		return ""
	}
	return strings.TrimSpace(a.Account.DeviceID)
}

// applyHIFHeaders merges the risk tokens into a header set. Missing tokens
// leave the request exactly as it was.
func (c *Client) applyHIFHeaders(ctx context.Context, a *auth.RequestAuth, headers map[string]string) {
	if headers == nil {
		return
	}
	for key, value := range c.hifHeaders(ctx, a) {
		if strings.TrimSpace(value) == "" {
			continue
		}
		headers[key] = value
	}
}

// scheduleHIFRefresh fetches the tokens for one device off the request path. At
// most one refresh per device runs at a time, so a burst of requests does not
// turn into a burst of fetches.
func (c *Client) scheduleHIFRefresh(ctx context.Context, a *auth.RequestAuth, deviceID string) {
	if c == nil || c.hif == nil || a == nil || deviceID == "" {
		return
	}
	if !c.hif.beginRefresh(deviceID) {
		return
	}
	account := a.Account
	token := a.DeepSeekToken
	bgCtx := context.WithoutCancel(ctx)
	go func() {
		defer c.hif.endRefresh(deviceID)
		refreshCtx, cancel := context.WithTimeout(bgCtx, 2*hifFetchTimeout)
		defer cancel()
		copyAuth := &auth.RequestAuth{
			UseConfigToken: true,
			DeepSeekToken:  token,
			AccountID:      account.Identifier(),
			Account:        account,
		}
		for _, kind := range hifKinds {
			warmCtx, warmCancel := context.WithTimeout(refreshCtx, hifFetchTimeout)
			_ = c.hifValue(warmCtx, copyAuth, deviceID, kind)
			warmCancel()
		}
	}()
}

func (c *Client) hifValue(ctx context.Context, a *auth.RequestAuth, deviceID string, kind hifKind) string {
	token := c.hif.token(deviceID, kind.name)
	token.mu.Lock()
	defer token.mu.Unlock()

	now := time.Now()
	if token.value != "" && token.expiresAt.After(now) {
		return token.value
	}
	if token.nextAttempt.After(now) {
		// Inside the backoff window: hand out the stale value if there is one
		// instead of paying another timeout on the request path.
		return token.value
	}

	value, ttl, err := c.fetchHIFToken(ctx, a, deviceID, kind)
	if err != nil {
		token.failures++
		token.nextAttempt = now.Add(hifFailureBackoff(token.failures))
		config.Logger.Debug("[hif] token fetch failed", "kind", kind.name, "account", a.AccountID, "failures", token.failures, "error", err)
		return token.value
	}
	token.value = value
	token.expiresAt = now.Add(ttl)
	token.nextAttempt = time.Time{}
	token.failures = 0
	config.Logger.Debug("[hif] token refreshed", "kind", kind.name, "account", a.AccountID, "ttl_seconds", int(ttl.Seconds()))
	return value
}

func (c *Client) fetchHIFToken(ctx context.Context, a *auth.RequestAuth, deviceID string, kind hifKind) (string, time.Duration, error) {
	clients := c.requestClientsForAuth(ctx, a)
	fetchCtx, cancel := context.WithTimeout(ctx, hifFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, kind.url, nil)
	if err != nil {
		return "", 0, err
	}
	for key, value := range hifRequestHeaders(a, deviceID) {
		req.Header.Set(key, value)
	}
	resp, err := clients.regular.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			config.Logger.Debug("[hif] close response body failed", "kind", kind.name, "error", closeErr)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, &hifStatusError{status: resp.StatusCode, preview: previewHIFBody(body)}
	}
	value := parseHIFValue(body)
	if value == "" {
		return "", 0, &hifStatusError{status: resp.StatusCode, preview: previewHIFBody(body)}
	}
	return value, hifTTLFromResponse(resp), nil
}

type hifStatusError struct {
	status  int
	preview string
}

func (e *hifStatusError) Error() string {
	return "hif token endpoint returned HTTP " + strconv.Itoa(e.status) + ": " + e.preview
}

func previewHIFBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > hifErrorBodyWindow {
		return text[:hifErrorBodyWindow]
	}
	return text
}

// hifRequestHeaders mirrors the page's own cross-site fetch: the client
// identity headers (no Authorization — the endpoint is unauthenticated), no
// Host/Content-Type override, plus the device the token is being asked for.
func hifRequestHeaders(a *auth.RequestAuth, deviceID string) map[string]string {
	locale := ""
	if a != nil {
		locale = strings.TrimSpace(a.Account.Locale)
	}
	headers := dsprotocol.BaseHeadersFor(locale)
	delete(headers, "Host")
	delete(headers, "Content-Type")
	headers["accept"] = "*/*"
	headers["origin"] = "https://chat.deepseek.com"
	headers["referer"] = "https://chat.deepseek.com/"
	// hif-*.deepseek.com is a sibling origin, so the page's fetch reports
	// `same-site`, not `same-origin`. BaseHeaders carries the chat.deepseek.com
	// value, which would be a same-origin claim about a cross-site request.
	headers["sec-fetch-site"] = "same-site"
	if deviceID != "" {
		headers["x-device-id"] = deviceID
		headers["x-device-model"] = ""
	}
	return headers
}

func hifTTLFromResponse(resp *http.Response) time.Duration {
	if resp == nil {
		return hifDefaultTTL
	}
	raw := strings.TrimSpace(resp.Header.Get("x-hif-ttl"))
	if raw == "" {
		return hifDefaultTTL
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return hifDefaultTTL
	}
	ttl := time.Duration(seconds) * time.Second
	// Refresh a little early so a still-valid token is not handed out at the
	// very edge of its window; keep at least one second of validity.
	if ttl > hifRefreshMargin {
		return ttl - hifRefreshMargin
	}
	return time.Second
}

// parseHIFValue unwraps {"code":0,"data":{"biz_code":0,"biz_data":{"value":"…"}}}.
func parseHIFValue(body []byte) string {
	var envelope struct {
		Code int `json:"code"`
		Data *struct {
			BizCode int `json:"biz_code"`
			BizData *struct {
				Value string `json:"value"`
			} `json:"biz_data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return ""
	}
	if envelope.Data == nil || envelope.Data.BizCode != 0 || envelope.Data.BizData == nil {
		return ""
	}
	value := strings.TrimSpace(envelope.Data.BizData.Value)
	if value == "" || len(value) > hifMaxValueLength {
		return ""
	}
	return value
}

// WarmUpHIF prefetches the two tokens for an account's device so the first
// business request does not pay the fetch (the page starts polling as soon as
// it boots). Failure is logged inside hifValue and otherwise ignored.
func (c *Client) WarmUpHIF(ctx context.Context, a *auth.RequestAuth) {
	if c == nil || c.hif == nil || a == nil || !c.hifTokensEnabled() {
		return
	}
	deviceID := accountDeviceID(a)
	if deviceID == "" {
		return
	}
	for _, kind := range hifKinds {
		_ = c.hifValue(ctx, a, deviceID, kind)
	}
}
