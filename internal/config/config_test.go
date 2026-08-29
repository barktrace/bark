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

func TestValidateS3BlobConfiguration(t *testing.T) {
	t.Parallel()
	base := Config{
		PublicURL: "https://errors.example", DefaultOrgSlug: "default", BlobBackend: "s3",
		OIDC: OIDC{IssuerURL: "https://id.example", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://errors.example/auth/oidc/callback"},
	}
	if err := base.validate(); err == nil {
		t.Fatal("incomplete S3 configuration passed validation")
	}
	base.S3 = S3{Endpoint: "https://s3.example", Bucket: "barktrace", AccessKey: "access", SecretKey: "secret"}
	if err := base.validate(); err != nil {
		t.Fatalf("valid S3 configuration: %v", err)
	}
	base.BlobBackend = "ftp"
	if err := base.validate(); err == nil {
		t.Fatal("unknown blob backend passed validation")
	}
}

func TestValidateRemoteSQLiteConfiguration(t *testing.T) {
	t.Parallel()
	base := Config{
		PublicURL: "https://errors.example", DefaultOrgSlug: "default",
		OIDC: OIDC{IssuerURL: "https://id.example", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://errors.example/auth/oidc/callback"},
	}
	for _, databaseURL := range []string{"libsql://database.example", "https://database.example", "wss://database.example", "http://127.0.0.1:8080", "ws://localhost:8080"} {
		cfg := base
		cfg.DatabaseURL = databaseURL
		if err := cfg.validate(); err != nil {
			t.Errorf("validate database URL %q: %v", databaseURL, err)
		}
	}
	for _, databaseURL := range []string{"postgres://database.example/db", "http://database.example", "libsql://token@database.example", "libsql://database.example?authToken=secret", "not-a-url"} {
		cfg := base
		cfg.DatabaseURL = databaseURL
		if err := cfg.validate(); err == nil {
			t.Errorf("database URL %q unexpectedly passed validation", databaseURL)
		}
	}
}
