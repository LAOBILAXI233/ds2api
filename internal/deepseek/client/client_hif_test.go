package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ds2api/internal/auth"
	"ds2api/internal/config"
)

type hifDoer struct {
	requests atomic.Int32
	lastReq  *http.Request
	status   int
	ttl      string
	body     string
	delay    time.Duration
}

func (d *hifDoer) Do(req *http.Request) (*http.Response, error) {
	d.requests.Add(1)
	d.lastReq = req
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	if d.ttl != "" {
		header.Set("x-hif-ttl", d.ttl)
	}
	body := d.body
	if body == "" {
		body = `{"code":0,"msg":"","data":{"biz_code":0,"biz_msg":"","biz_data":{"value":"token-` + req.URL.Host + `"}}}`
	}
	status := d.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func hifTestClient(doer *hifDoer) *Client {
	return &Client{
		regular: doer,
		hif:     newHIFRegistry(),
	}
}

func hifTestAuth(deviceID string) *auth.RequestAuth {
	return &auth.RequestAuth{
		UseConfigToken: true,
		DeepSeekToken:  "token",
		AccountID:      "acct",
		Account:        config.Account{Email: "u@example.com", DeviceID: deviceID},
	}
}

// waitFor polls until cond holds or the deadline expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The request path must never wait on a token fetch: time-to-first-token is the
// property this gateway is built around.
func TestHIFHeadersNeverBlockOnFetch(t *testing.T) {
	doer := &hifDoer{ttl: "600", delay: 300 * time.Millisecond}
	client := hifTestClient(doer)
	a := hifTestAuth("device-block")

	started := time.Now()
	headers := client.hifHeaders(context.Background(), a)
	elapsed := time.Since(started)

	if len(headers) != 0 {
		t.Fatalf("expected no headers on a cold cache, got %#v", headers)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("hifHeaders blocked for %s; it must schedule the fetch instead", elapsed)
	}
	// The scheduled refresh still lands, so the next request can carry the
	// headers.
	waitFor(t, 3*time.Second, func() bool {
		return client.hifHeaders(context.Background(), a)["x-hif-leim"] != ""
	}, "background token fetch")
}

func TestWarmUpHIFPopulatesCacheSynchronously(t *testing.T) {
	doer := &hifDoer{ttl: "600"}
	client := hifTestClient(doer)
	a := hifTestAuth("11111111-1111-4111-8111-111111111111")

	client.WarmUpHIF(context.Background(), a)

	headers := client.hifHeaders(context.Background(), a)
	if headers["x-hif-leim"] == "" || headers["x-hif-dliq"] == "" {
		t.Fatalf("expected both tokens after warm-up, got %#v", headers)
	}
	if got := doer.requests.Load(); got != 2 {
		t.Fatalf("expected one fetch per endpoint, got %d", got)
	}
	// The request carries the device identity and no bearer token.
	if got := doer.lastReq.Header.Get("x-device-id"); got != a.Account.DeviceID {
		t.Fatalf("expected x-device-id=%q, got %q", a.Account.DeviceID, got)
	}
	if got := doer.lastReq.Header.Get("authorization"); got != "" {
		t.Fatalf("hif token endpoint must not carry authorization, got %q", got)
	}

	// A second call is served from the cache.
	_ = client.hifHeaders(context.Background(), a)
	if got := doer.requests.Load(); got != 2 {
		t.Fatalf("expected no extra fetch, got %d", got)
	}
}

func TestHIFHeadersAreCachedPerDevice(t *testing.T) {
	doer := &hifDoer{ttl: "600"}
	client := hifTestClient(doer)

	client.WarmUpHIF(context.Background(), hifTestAuth("device-a"))
	client.WarmUpHIF(context.Background(), hifTestAuth("device-b"))

	if got := doer.requests.Load(); got != 4 {
		t.Fatalf("expected each device to fetch its own tokens, got %d requests", got)
	}
	if client.hifHeaders(context.Background(), hifTestAuth("device-a"))["x-hif-leim"] == "" {
		t.Fatal("expected device-a to keep its own cached token")
	}
}

func TestHIFHeadersFailureIsNotFatal(t *testing.T) {
	doer := &hifDoer{status: http.StatusInternalServerError, body: "boom"}
	client := hifTestClient(doer)
	a := hifTestAuth("device-c")

	if headers := client.hifHeaders(context.Background(), a); len(headers) != 0 {
		t.Fatalf("expected no headers when the endpoints fail, got %#v", headers)
	}
	waitFor(t, 3*time.Second, func() bool { return doer.requests.Load() >= 2 }, "failed fetch attempts")
	// A stale entry first, then the backoff: no further attempts pile up.
	first := doer.requests.Load()
	_ = client.hifHeaders(context.Background(), a)
	time.Sleep(50 * time.Millisecond)
	if got := doer.requests.Load(); got != first {
		t.Fatalf("expected the backoff to suppress retries, got %d then %d", first, got)
	}
}

func TestHIFHeadersRefetchesAfterTTL(t *testing.T) {
	doer := &hifDoer{ttl: "1"}
	client := hifTestClient(doer)
	a := hifTestAuth("device-d")

	client.WarmUpHIF(context.Background(), a)
	before := doer.requests.Load()
	time.Sleep(1100 * time.Millisecond)
	// The expired value is still handed out while the refresh is scheduled.
	headers := client.hifHeaders(context.Background(), a)
	if headers["x-hif-leim"] == "" {
		t.Fatal("expected the stale token to be reused rather than dropped")
	}
	waitFor(t, 3*time.Second, func() bool { return doer.requests.Load() > before }, "ttl refresh")
}

func TestHIFHeadersDisabledByEnv(t *testing.T) {
	t.Setenv("DS2API_HIF_TOKENS", "0")
	doer := &hifDoer{ttl: "600"}
	client := hifTestClient(doer)

	if headers := client.hifHeaders(context.Background(), hifTestAuth("device-e")); len(headers) != 0 {
		t.Fatalf("expected no headers when disabled, got %#v", headers)
	}
	client.WarmUpHIF(context.Background(), hifTestAuth("device-e"))
	if got := doer.requests.Load(); got != 0 {
		t.Fatalf("expected no fetches when disabled, got %d", got)
	}
}

func TestParseHIFValue(t *testing.T) {
	body := []byte(`{"code":0,"msg":"","data":{"biz_code":0,"biz_msg":"","biz_data":{"value":"ALytJQRz.bf4ojFDX"}}}`)
	if got := parseHIFValue(body); got != "ALytJQRz.bf4ojFDX" {
		t.Fatalf("unexpected value %q", got)
	}
	if got := parseHIFValue([]byte(`{"code":40002,"msg":"no"}`)); got != "" {
		t.Fatalf("expected empty value, got %q", got)
	}
}

func TestApplyDeviceHeaders(t *testing.T) {
	headers := map[string]string{}
	applyDeviceHeaders(headers, " 11111111-2222-4333-8444-555555555555 ")
	if headers["x-device-id"] != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("unexpected device header: %#v", headers)
	}
	if value, ok := headers["x-device-model"]; !ok || value != "" {
		t.Fatalf("expected an empty device model header, got %#v", headers)
	}
	plain := map[string]string{}
	applyDeviceHeaders(plain, "   ")
	if len(plain) != 0 {
		t.Fatalf("expected no headers for an empty device id, got %#v", plain)
	}
}
