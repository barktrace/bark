package config

import "testing"

func TestValidateOIDCIssuerTransport(t *testing.T) {
	t.Parallel()
	base := Config{
		PublicURL:      "https://errors.example",
		DefaultOrgSlug: "default",
		OIDC: OIDC{
			ClientID:     "client",
			ClientSecret: "secret",
			RedirectURL:  "https://errors.example/auth/oidc/callback",
		},
	}

	for _, issuer := range []string{"https://id.example", "http://localhost:1411", "http://127.0.0.1:1411", "http://[::1]:1411"} {
		cfg := base
		cfg.OIDC.IssuerURL = issuer
		if err := cfg.validate(); err != nil {
			t.Errorf("validate issuer %q: %v", issuer, err)
		}
	}
	for _, issuer := range []string{"http://id.example", "http://localhost.evil.example", "not-a-url"} {
		cfg := base
		cfg.OIDC.IssuerURL = issuer
		if err := cfg.validate(); err == nil {
			t.Errorf("issuer %q unexpectedly passed validation", issuer)
		}
	}
}

func TestValidateMCPTokenLength(t *testing.T) {
	t.Parallel()
	cfg := Config{
		PublicURL:      "https://errors.example",
		DefaultOrgSlug: "default",
		MCPToken:       "too-short",
		OIDC: OIDC{
			IssuerURL:    "https://id.example",
			ClientID:     "client",
			ClientSecret: "secret",
			RedirectURL:  "https://errors.example/auth/oidc/callback",
		},
	}
	if err := cfg.validate(); err == nil {
		t.Fatal("short MCP token unexpectedly passed validation")
	}
}
