package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type OIDC struct {
	IssuerURL            string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	ProviderName         string
	Scopes               []string
	RequireEmailVerified bool
}

type Config struct {
	Addr                      string
	DataDir                   string
	PublicURL                 string
	DefaultOrgName            string
	DefaultOrgSlug            string
	AutoProvision             bool
	SecureCookies             bool
	SessionLifetime           time.Duration
	MaxEnvelopeBytes          int64
	MCPToken                  string
	UptimeAllowPrivateTargets bool
	OIDC                      OIDC
}

func Load() (Config, error) {
	cfg := Config{
		Addr:                      env("BARKTRACE_ADDR", ":8080"),
		DataDir:                   env("BARKTRACE_DATA_DIR", "./data"),
		PublicURL:                 strings.TrimRight(env("BARKTRACE_PUBLIC_URL", "http://localhost:8080"), "/"),
		DefaultOrgName:            env("BARKTRACE_DEFAULT_ORG_NAME", "Default"),
		DefaultOrgSlug:            env("BARKTRACE_DEFAULT_ORG_SLUG", "default"),
		AutoProvision:             envBool("BARKTRACE_AUTO_PROVISION", true),
		SessionLifetime:           30 * 24 * time.Hour,
		MaxEnvelopeBytes:          20 << 20,
		MCPToken:                  strings.TrimSpace(os.Getenv("BARKTRACE_MCP_TOKEN")),
		UptimeAllowPrivateTargets: envBool("BARKTRACE_UPTIME_ALLOW_PRIVATE_TARGETS", false),
		OIDC: OIDC{
			IssuerURL:            strings.TrimRight(strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")), "/"),
			ClientID:             strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
			ClientSecret:         os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURL:          strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL")),
			ProviderName:         env("OIDC_PROVIDER_NAME", "SSO"),
			Scopes:               strings.Fields(env("OIDC_SCOPES", "openid email profile")),
			RequireEmailVerified: envBool("OIDC_REQUIRE_EMAIL_VERIFIED", true),
		},
	}
	cfg.SecureCookies = strings.HasPrefix(strings.ToLower(cfg.PublicURL), "https://")
	if value := strings.TrimSpace(os.Getenv("BARKTRACE_SESSION_LIFETIME_HOURS")); value != "" {
		hours, err := strconv.Atoi(value)
		if err != nil || hours < 1 {
			return Config{}, fmt.Errorf("BARKTRACE_SESSION_LIFETIME_HOURS must be a positive integer")
		}
		cfg.SessionLifetime = time.Duration(hours) * time.Hour
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	absolute, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return Config{}, fmt.Errorf("resolve data directory: %w", err)
	}
	cfg.DataDir = absolute
	return cfg, nil
}

func (c Config) validate() error {
	if err := validateHTTPSOrLoopback("BARKTRACE_PUBLIC_URL", c.PublicURL); err != nil {
		return err
	}
	if c.DefaultOrgSlug == "" {
		return errors.New("BARKTRACE_DEFAULT_ORG_SLUG is required")
	}
	missing := make([]string, 0, 4)
	for name, value := range map[string]string{
		"OIDC_ISSUER_URL":    c.OIDC.IssuerURL,
		"OIDC_CLIENT_ID":     c.OIDC.ClientID,
		"OIDC_CLIENT_SECRET": c.OIDC.ClientSecret,
		"OIDC_REDIRECT_URL":  c.OIDC.RedirectURL,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("SSO is required; missing %s", strings.Join(missing, ", "))
	}
	if c.MCPToken != "" && len(c.MCPToken) < 32 {
		return errors.New("BARKTRACE_MCP_TOKEN must be at least 32 characters when set")
	}
	if err := validateHTTPSOrLoopback("OIDC_ISSUER_URL", c.OIDC.IssuerURL); err != nil {
		return err
	}
	if err := validateHTTPSOrLoopback("OIDC_REDIRECT_URL", c.OIDC.RedirectURL); err != nil {
		return err
	}
	publicURL, _ := url.Parse(c.PublicURL)
	if publicURL.Path != "" && publicURL.Path != "/" {
		return errors.New("BARKTRACE_PUBLIC_URL must not contain a path")
	}
	return nil
}

func validateHTTPSOrLoopback(name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("%s must be a valid absolute URL", name)
	}
	loopback := strings.EqualFold(parsed.Hostname(), "localhost")
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !(strings.EqualFold(parsed.Scheme, "http") && loopback) {
		return fmt.Errorf("%s must use HTTPS (loopback HTTP is allowed for development)", name)
	}
	return nil
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
