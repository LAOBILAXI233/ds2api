package config

import "testing"

func boolPtr(v bool) *bool { return &v }

// Session tokens must not be written to config.json — except when the token IS
// the account. A token-only account (no password) was created by pasting a
// browser session; wiping its token on save would delete the account on the next
// restart, which is exactly when it cannot be re-created.
func TestClearAccountTokensKeepsTokenOnlyAccounts(t *testing.T) {
	cfg := &Config{Accounts: []Account{
		{Email: "password@example.com", Password: "pwd", Token: "signed-in-token"},
		{Email: "imported@example.com", Token: "pasted-token"},
		{Email: "empty@example.com"},
	}}

	cfg.ClearAccountTokens()

	if cfg.Accounts[0].Token != "" {
		t.Fatalf("expected the signed-in token to be dropped, got %q", cfg.Accounts[0].Token)
	}
	if cfg.Accounts[1].Token != "pasted-token" {
		t.Fatalf("expected the token-only account to keep its token, got %q", cfg.Accounts[1].Token)
	}
}

// An operator whose deployment cannot sign in at all opts out of the whole rule.
func TestClearAccountTokensRespectsPersistTokens(t *testing.T) {
	cfg := &Config{
		Runtime:  RuntimeConfig{PersistTokens: boolPtr(true)},
		Accounts: []Account{{Email: "password@example.com", Password: "pwd", Token: "live-token"}},
	}

	cfg.ClearAccountTokens()

	if cfg.Accounts[0].Token != "live-token" {
		t.Fatalf("expected persist_tokens to keep the token, got %q", cfg.Accounts[0].Token)
	}
	if !cfg.TokensPersist() {
		t.Fatal("TokensPersist should report the switch as on")
	}
}

func TestTokensPersistDefaultsToOff(t *testing.T) {
	if (&Config{}).TokensPersist() {
		t.Fatal("persist_tokens must default to off")
	}
	if (&Config{Runtime: RuntimeConfig{PersistTokens: boolPtr(false)}}).TokensPersist() {
		t.Fatal("an explicit false must stay off")
	}
}
