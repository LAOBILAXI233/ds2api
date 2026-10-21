package config

import (
	"encoding/json"
	"os"
	"testing"
)

// The shipped example must always decode into the real config types: it is what
// the admin console's full-config template and the docker/vercel instructions
// point people at.
func TestExampleConfigDecodes(t *testing.T) {
	raw, err := os.ReadFile("../../config.example.json")
	if err != nil {
		t.Fatalf("read config.example.json: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("decode config.example.json: %v", err)
	}
	if cfg.Runtime.HIFTokens == nil || !*cfg.Runtime.HIFTokens {
		t.Fatalf("expected runtime.hif_tokens to decode as true, got %#v", cfg.Runtime.HIFTokens)
	}
	if cfg.Runtime.WarmUpOnStartup == nil || !*cfg.Runtime.WarmUpOnStartup {
		t.Fatalf("expected runtime.warm_up_on_startup to decode as true, got %#v", cfg.Runtime.WarmUpOnStartup)
	}
	if len(cfg.Accounts) == 0 {
		t.Fatal("expected example accounts")
	}
}
