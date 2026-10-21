package client

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ds2api/internal/auth"
	"ds2api/internal/config"
	trans "ds2api/internal/deepseek/transport"
	"ds2api/internal/devcapture"
	"ds2api/internal/util"
)

// intFrom is a package-internal alias for the shared util version.
var intFrom = util.IntFrom

type Client struct {
	Store      *config.Store
	Auth       *auth.Resolver
	capture    *devcapture.Store
	regular    trans.Doer
	stream     trans.Doer
	fallback   *http.Client
	fallbackS  *http.Client
	maxRetries int

	powCache *powChallengeCache
	cookies  *cookieJar
	// hif caches the web client's x-hif-leim / x-hif-dliq risk tokens per
	// device identity (see client_hif.go).
	hif *hifRegistry

	proxyClientsMu sync.RWMutex
	proxyClients   map[string]requestClients
}

func NewClient(store *config.Store, resolver *auth.Resolver) *Client {
	var fallbackTr http.RoundTripper
	if os.Getenv("DS2API_INSECURE_SKIP_VERIFY") == "true" || os.Getenv("DS2API_SKIP_TLS_VERIFY") == "true" {
		fallbackTr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &Client{
		Store:        store,
		Auth:         resolver,
		capture:      devcapture.Global(),
		regular:      trans.New(60 * time.Second),
		stream:       trans.New(0),
		fallback:     &http.Client{Timeout: 60 * time.Second, Transport: fallbackTr},
		fallbackS:    &http.Client{Timeout: 0, Transport: fallbackTr},
		maxRetries:   3,
		proxyClients: map[string]requestClients{},
		powCache:     newPowChallengeCache(),
		cookies:      newCookieJar(),
		hif:          newHIFRegistry(),
	}
	if resolver != nil {
		resolver.PostLogin = func(ctx context.Context, a *auth.RequestAuth) {
			client.reportClientSettingsAfterLogin(ctx, a, "")
		}
		// The token sweeper validates an unaged token instead of signing in
		// again: /users/current answers "is this a live session" with no proof
		// of work and no chat, which is the cheapest question upstream allows.
		resolver.Validate = func(ctx context.Context, acc config.Account, token string) error {
			if strings.TrimSpace(token) == "" {
				return auth.NewLoginError(0, "no token to validate")
			}
			probe := &auth.RequestAuth{
				UseConfigToken: true,
				DeepSeekToken:  strings.TrimSpace(token),
				AccountID:      acc.Identifier(),
				Account:        acc,
			}
			user, err := client.CurrentUser(ctx, probe)
			if err != nil {
				if failure, ok := err.(*RequestFailure); ok {
					if failure.Kind == FailureManagedUnauthorized || failure.Kind == FailureDirectUnauthorized {
						// The token is not a live session: a refresh is due.
						return auth.NewLoginError(0, failure.Message)
					}
				}
				return err
			}
			if user.IsMuted {
				return auth.NewLoginError(auth.LoginCodeMuted, "account is muted")
			}
			return nil
		}
	}
	return client
}

// PreloadPow 保留兼容接口，纯 Go 实现无需预加载。
func (c *Client) PreloadPow(_ context.Context) error {
	return nil
}
