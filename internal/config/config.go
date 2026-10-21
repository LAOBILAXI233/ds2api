package config

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

type Config struct {
	Keys                 []string                   `json:"keys,omitempty"`
	APIKeys              []APIKey                   `json:"api_keys,omitempty"`
	Accounts             []Account                  `json:"accounts,omitempty"`
	Proxies              []Proxy                    `json:"proxies,omitempty"`
	ModelAliases         map[string]string          `json:"model_aliases,omitempty"`
	Admin                AdminConfig                `json:"admin,omitempty"`
	Runtime              RuntimeConfig              `json:"runtime,omitempty"`
	Responses            ResponsesConfig            `json:"responses,omitempty"`
	Embeddings           EmbeddingsConfig           `json:"embeddings,omitempty"`
	AutoDelete           AutoDeleteConfig           `json:"auto_delete"`
	CurrentInputFile     CurrentInputFileConfig     `json:"current_input_file,omitempty"`
	ThinkingInjection    ThinkingInjectionConfig    `json:"thinking_injection,omitempty"`
	ExpertTextFileInline ExpertTextFileInlineConfig `json:"expert_text_file_inline,omitempty"`
	ExpertPromptSegment  ExpertPromptSegmentConfig  `json:"expert_prompt_segment,omitempty"`
	AutoRouteVision      AutoRouteVisionConfig      `json:"auto_route_vision,omitempty"`
	ElasticPool          ElasticPoolConfig          `json:"elastic_pool,omitempty"`
	Vercel               VercelConfig               `json:"vercel,omitempty"`
	VercelSyncHash       string                     `json:"_vercel_sync_hash,omitempty"`
	VercelSyncTime       int64                      `json:"_vercel_sync_time,omitempty"`
	AdditionalFields     map[string]any             `json:"-"`
}

type Account struct {
	Name string `json:"name,omitempty"`
	// UserID 是上游的账号 id（/users/current 的 biz_data.id）。
	// 只有导入令牌的账号需要它：上游把邮箱/手机号打码后才返回
	// （如 ryona******@…），打码值不能当账号标识，重复导入也无法据此匹配。
	UserID         string  `json:"user_id,omitempty"`
	Remark         string  `json:"remark,omitempty"`
	Email          string  `json:"email,omitempty"`
	Mobile         string  `json:"mobile,omitempty"`
	Password       string  `json:"password,omitempty"`
	Token          string  `json:"token,omitempty"`
	DeviceID       string  `json:"device_id,omitempty"`
	ProxyID        string  `json:"proxy_id,omitempty"`
	PoolType       string  `json:"pool_type,omitempty"`
	Locale         string  `json:"locale,omitempty"`
	Disabled       bool    `json:"disabled,omitempty"`
	DisabledReason string  `json:"disabled_reason,omitempty"`
	Banned         bool    `json:"banned,omitempty"`
	MutedUntil     float64 `json:"muted_until,omitempty"`
	// CooldownUntil 是本地风控冷却到期时间（Unix 秒）。
	// 与 MutedUntil 不同：MutedUntil 由上游下发，CooldownUntil 是我们自己
	// 在收到验证码挑战后主动设置的——挑战意味着风控已经盯上这个账号，
	// 继续用它只会把情况变得更糟。
	CooldownUntil float64 `json:"cooldown_until,omitempty"`
	// TokenRefreshedAt 是令牌最近一次成功登录/刷新的 Unix 秒时间戳。
	// 持久化它，是为了让"令牌有多老"跨进程重启仍然成立——重启不该成为
	// 重新登录每个账号的理由。
	TokenRefreshedAt float64 `json:"token_refreshed_at,omitempty"`
	// RefreshFailures 是连续刷新失败次数；一次成功即清零。
	RefreshFailures int `json:"refresh_failures,omitempty"`
	// RefreshError 是最近一次刷新失败的可读原因（诊断用）。
	RefreshError string `json:"refresh_error,omitempty"`
	// RefreshRetryAt 是失败退避后允许再次尝试刷新的 Unix 秒时间戳。
	RefreshRetryAt float64 `json:"refresh_retry_at,omitempty"`
}

type APIKey struct {
	Key          string `json:"key"`
	Name         string `json:"name,omitempty"`
	Remark       string `json:"remark,omitempty"`
	ToolsEnabled bool   `json:"tools_enabled,omitempty"`
}

type Proxy struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func NormalizeProxy(p Proxy) Proxy {
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	p.Host = strings.TrimSpace(p.Host)
	p.Username = strings.TrimSpace(p.Username)
	p.Password = strings.TrimSpace(p.Password)
	if p.ID == "" {
		p.ID = StableProxyID(p)
	}
	if p.Name == "" && p.Host != "" && p.Port > 0 {
		p.Name = fmt.Sprintf("%s:%d", p.Host, p.Port)
	}
	return p
}

func StableProxyID(p Proxy) string {
	sum := sha1.Sum([]byte(strings.ToLower(strings.TrimSpace(p.Type)) + "|" + strings.ToLower(strings.TrimSpace(p.Host)) + "|" + fmt.Sprintf("%d", p.Port) + "|" + strings.TrimSpace(p.Username)))
	return "proxy_" + hex.EncodeToString(sum[:6])
}

// ClearAccountTokens drops the session tokens this process obtained by signing in
// before a config is written to disk: they are short-lived, and a live session
// credential does not belong in config.json when the password that produced it
// is already there.
//
// An account with NO password is the exception, and it is the reason this is not
// a blanket wipe. Such an account exists only because its token was pasted in
// (see POST /admin/accounts/import-token) — usually because the sign-in endpoint
// refuses this deployment — so its token is the one and only credential it has.
// Clearing it would not protect anything: it would silently delete the account
// on the next restart, which is exactly when it cannot be re-created.
//
// Operators whose deployment cannot sign in at all opt out of the whole rule with
// runtime.persist_tokens (see RuntimeConfig.PersistTokens).
func (c *Config) ClearAccountTokens() {
	if c == nil || c.TokensPersist() {
		return
	}
	for i := range c.Accounts {
		if strings.TrimSpace(c.Accounts[i].Password) == "" && strings.TrimSpace(c.Accounts[i].Token) != "" {
			continue
		}
		c.Accounts[i].Token = ""
	}
}

func (c *Config) NormalizeCredentials() {
	if c == nil {
		return
	}
	normalizedAPIKeys := normalizeAPIKeys(c.APIKeys)
	if len(normalizedAPIKeys) > 0 {
		c.APIKeys = normalizedAPIKeys
		c.Keys = apiKeysToStrings(c.APIKeys)
	} else {
		c.Keys = normalizeKeys(c.Keys)
		c.APIKeys = apiKeysFromStrings(c.Keys, nil)
	}

	for i := range c.Accounts {
		c.Accounts[i].Name = strings.TrimSpace(c.Accounts[i].Name)
		c.Accounts[i].Remark = strings.TrimSpace(c.Accounts[i].Remark)
		c.Accounts[i].DeviceID = strings.TrimSpace(c.Accounts[i].DeviceID)
		c.Accounts[i].Locale = strings.TrimSpace(c.Accounts[i].Locale)
		c.Accounts[i].PoolType = NormalizePoolType(c.Accounts[i].PoolType)
	}

	c.Vercel = NormalizeVercelConfig(c.Vercel)
	c.normalizeModelAliases()
}

// DropInvalidAccounts removes accounts that cannot be addressed by admin APIs
// (no email and no normalizable mobile). This prevents legacy token-only
// records from becoming orphaned empty entries after token stripping.
func (c *Config) DropInvalidAccounts() {
	if c == nil || len(c.Accounts) == 0 {
		return
	}
	kept := make([]Account, 0, len(c.Accounts))
	for _, acc := range c.Accounts {
		if acc.Identifier() == "" {
			continue
		}
		kept = append(kept, acc)
	}
	c.Accounts = kept
}

func (c *Config) normalizeModelAliases() {
	if c == nil {
		return
	}

	aliases := map[string]string{}
	for k, v := range c.ModelAliases {
		key := strings.TrimSpace(lower(k))
		val := strings.TrimSpace(lower(v))
		if key == "" || val == "" {
			continue
		}
		aliases[key] = val
	}
	if len(aliases) == 0 {
		c.ModelAliases = nil
	} else {
		c.ModelAliases = aliases
	}
}

type AdminConfig struct {
	PasswordHash      string `json:"password_hash,omitempty"`
	JWTExpireHours    int    `json:"jwt_expire_hours,omitempty"`
	JWTValidAfterUnix int64  `json:"jwt_valid_after_unix,omitempty"`
}

type RuntimeConfig struct {
	AccountMaxInflight        int `json:"account_max_inflight,omitempty"`
	AccountMaxQueue           int `json:"account_max_queue,omitempty"`
	GlobalMaxInflight         int `json:"global_max_inflight,omitempty"`
	TokenRefreshIntervalHours int `json:"token_refresh_interval_hours,omitempty"`
	// HIFTokens 控制是否在 completion / continue / resume 请求上回传网页端
	// 风控令牌 x-hif-leim / x-hif-dliq。nil = 默认开启（与网页端一致）。
	// 令牌按账号自己的 X-Device-Id 缓存，多账号不会共用同一份。
	HIFTokens *bool `json:"hif_tokens,omitempty"`
	// WarmUpOnStartup 控制启动时是否预热各账号（登录/续期 + 令牌 + 风控令牌），
	// nil = 默认开启。关闭后账号在首个请求到来时才登录。
	WarmUpOnStartup *bool `json:"warm_up_on_startup,omitempty"`
	// PersistTokens 控制是否把会话令牌写进 config.json（默认关闭）。
	// 默认行为：登录换来的令牌只留在内存里，进程退出即失效——密码还在，重启后
	// 重新登录即可。开启后令牌会落盘，重启不必再登录；代价是 config.json 里会
	// 出现可用的会话凭证，需要自己保证文件权限。
	// 只在登录接口对本机被风控拒绝（RISK_DEVICE_DETECTED）时才值得打开。
	PersistTokens *bool `json:"persist_tokens,omitempty"`
}

// TokensPersist reports whether session tokens are written to config.json.
func (c *Config) TokensPersist() bool {
	return c != nil && c.Runtime.PersistTokens != nil && *c.Runtime.PersistTokens
}

type ResponsesConfig struct {
	StoreTTLSeconds int `json:"store_ttl_seconds,omitempty"`
}

type EmbeddingsConfig struct {
	Provider string `json:"provider,omitempty"`
}

type AutoDeleteConfig struct {
	Mode     string `json:"mode,omitempty"`
	Sessions bool   `json:"sessions,omitempty"`
}

type CurrentInputFileConfig struct {
	Enabled  *bool `json:"enabled,omitempty"`
	MinChars int   `json:"min_chars,omitempty"`
}

type ThinkingInjectionConfig struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Prompt  string `json:"prompt,omitempty"`
}

type ExpertPromptSegmentConfig struct {
	Enabled  *bool `json:"enabled,omitempty"`
	MaxChars int   `json:"max_chars,omitempty"`
}

type ExpertTextFileInlineConfig struct {
	Enabled           *bool    `json:"enabled,omitempty"`
	MaxFileBytes      int      `json:"max_file_bytes,omitempty"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
}

type AutoRouteVisionConfig struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// ElasticPoolConfig 控制弹性号池行为。
// 开启后按 config.Accounts 原始顺序在未禁言账号中启用前 N 个，
// 其余禁用；封号(muted)账号一律禁用且不占名额。
// PerPool=false 时所有账号共用 GlobalCount；PerPool=true 时
// default/no_tools/tools_only 三种号池类型分别使用各自的 Count。
type ElasticPoolConfig struct {
	Enabled        bool `json:"enabled,omitempty"`
	PerPool        bool `json:"per_pool,omitempty"`
	GlobalCount    int  `json:"global_count,omitempty"`
	DefaultCount   int  `json:"default_count,omitempty"`
	NoToolsCount   int  `json:"no_tools_count,omitempty"`
	ToolsOnlyCount int  `json:"tools_only_count,omitempty"`
}

type VercelConfig struct {
	Token     string `json:"token,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	TeamID    string `json:"team_id,omitempty"`
}

func NormalizeVercelConfig(v VercelConfig) VercelConfig {
	return VercelConfig{
		Token:     strings.TrimSpace(v.Token),
		ProjectID: strings.TrimSpace(v.ProjectID),
		TeamID:    strings.TrimSpace(v.TeamID),
	}
}

func (c *Config) ClearVercelCredentials() {
	if c == nil {
		return
	}
	c.Vercel = VercelConfig{}
}
