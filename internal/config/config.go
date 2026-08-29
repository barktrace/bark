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

type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLSMode  string
}

type S3 struct {
	Endpoint     string
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	Prefix       string
	AllowHTTP    bool
}

type Config struct {
	Addr                      string
	DataDir                   string
	DatabaseURL               string
	DatabaseAuthToken         string
	PublicURL                 string
	DefaultOrgName            string
	DefaultOrgSlug            string
	AutoProvision             bool
	SecureCookies             bool
	SessionLifetime           time.Duration
	MaxEnvelopeBytes          int64
	RateLimitPerMinute        int
	MCPToken                  string
	UptimeAllowPrivateTargets bool
	BlobBackend               string
	S3                        S3
	SMTP                      SMTP
	OIDC                      OIDC
}

func Load() (Config, error) {
	cfg := Config{
		Addr:                      env("BARKTRACE_ADDR", ":8080"),
		DataDir:                   env("BARKTRACE_DATA_DIR", "./data"),
		DatabaseURL:               strings.TrimSpace(os.Getenv("BARKTRACE_DATABASE_URL")),
		DatabaseAuthToken:         os.Getenv("BARKTRACE_DATABASE_AUTH_TOKEN"),
		PublicURL:                 strings.TrimRight(env("BARKTRACE_PUBLIC_URL", "http://localhost:8080"), "/"),
		DefaultOrgName:            env("BARKTRACE_DEFAULT_ORG_NAME", "Default"),
		DefaultOrgSlug:            env("BARKTRACE_DEFAULT_ORG_SLUG", "default"),
		AutoProvision:             envBool("BARKTRACE_AUTO_PROVISION", true),
		SessionLifetime:           30 * 24 * time.Hour,
		MaxEnvelopeBytes:          20 << 20,
		RateLimitPerMinute:        1000,
		MCPToken:                  strings.TrimSpace(os.Getenv("BARKTRACE_MCP_TOKEN")),
		UptimeAllowPrivateTargets: envBool("BARKTRACE_UPTIME_ALLOW_PRIVATE_TARGETS", false),
		BlobBackend:               strings.ToLower(env("BARKTRACE_BLOB_BACKEND", "local")),
		S3: S3{
			Endpoint: strings.TrimSpace(os.Getenv("BARKTRACE_S3_ENDPOINT")), Region: env("BARKTRACE_S3_REGION", "us-east-1"),
			Bucket: strings.TrimSpace(os.Getenv("BARKTRACE_S3_BUCKET")), AccessKey: strings.TrimSpace(os.Getenv("BARKTRACE_S3_ACCESS_KEY_ID")),
			SecretKey: os.Getenv("BARKTRACE_S3_SECRET_ACCESS_KEY"), SessionToken: os.Getenv("BARKTRACE_S3_SESSION_TOKEN"),
			Prefix: strings.TrimSpace(os.Getenv("BARKTRACE_S3_PREFIX")), AllowHTTP: envBool("BARKTRACE_S3_ALLOW_HTTP", false),
		},
		SMTP: SMTP{
			Host: strings.TrimSpace(os.Getenv("SMTP_HOST")), Username: strings.TrimSpace(os.Getenv("SMTP_USERNAME")), Password: os.Getenv("SMTP_PASSWORD"), From: strings.TrimSpace(os.Getenv("SMTP_FROM")), TLSMode: strings.ToLower(env("SMTP_TLS_MODE", "starttls")),
			Port: 587,
		},
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
	if value := strings.TrimSpace(os.Getenv("SMTP_PORT")); value != "" {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return Config{}, fmt.Errorf("SMTP_PORT must be between 1 and 65535")
		}
		cfg.SMTP.Port = port
	}
	cfg.SecureCookies = strings.HasPrefix(strings.ToLower(cfg.PublicURL), "https://")
	if value := strings.TrimSpace(os.Getenv("BARKTRACE_SESSION_LIFETIME_HOURS")); value != "" {
		hours, err := strconv.Atoi(value)
		if err != nil || hours < 1 {
			return Config{}, fmt.Errorf("BARKTRACE_SESSION_LIFETIME_HOURS must be a positive integer")
		}
		cfg.SessionLifetime = time.Duration(hours) * time.Hour
	}
	if value := strings.TrimSpace(os.Getenv("BARKTRACE_RATE_LIMIT_PER_MINUTE")); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 1 {
			return Config{}, fmt.Errorf("BARKTRACE_RATE_LIMIT_PER_MINUTE must be a positive integer")
		}
		cfg.RateLimitPerMinute = limit
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
	if c.DatabaseURL != "" {
		databaseURL, err := url.Parse(c.DatabaseURL)
		if err != nil || databaseURL.Host == "" {
			return errors.New("BARKTRACE_DATABASE_URL must be a valid absolute libSQL URL")
		}
		switch strings.ToLower(databaseURL.Scheme) {
		case "libsql", "https", "wss":
		case "http", "ws":
			loopback := strings.EqualFold(databaseURL.Hostname(), "localhost")
			if ip := net.ParseIP(databaseURL.Hostname()); ip != nil && ip.IsLoopback() {
				loopback = true
			}
			if !loopback {
				return errors.New("BARKTRACE_DATABASE_URL must use TLS (loopback HTTP is allowed for development)")
			}
		default:
			return errors.New("BARKTRACE_DATABASE_URL must use libsql, https, wss, or loopback http/ws")
		}
		if databaseURL.User != nil || databaseURL.RawQuery != "" {
			return errors.New("BARKTRACE_DATABASE_URL must not contain credentials or query parameters; use BARKTRACE_DATABASE_AUTH_TOKEN")
		}
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
	blobBackend := c.BlobBackend
	if blobBackend == "" {
		blobBackend = "local"
	}
	if blobBackend != "local" && blobBackend != "s3" {
		return errors.New("BARKTRACE_BLOB_BACKEND must be local or s3")
	}
	if blobBackend == "s3" {
		if c.S3.Endpoint == "" || c.S3.Bucket == "" || c.S3.AccessKey == "" || c.S3.SecretKey == "" {
			return errors.New("S3 blob storage requires BARKTRACE_S3_ENDPOINT, BARKTRACE_S3_BUCKET, BARKTRACE_S3_ACCESS_KEY_ID, and BARKTRACE_S3_SECRET_ACCESS_KEY")
		}
	}
	if c.SMTP.Host != "" {
		if c.SMTP.From == "" {
			return errors.New("SMTP_FROM is required when SMTP_HOST is set")
		}
		if c.SMTP.TLSMode != "starttls" && c.SMTP.TLSMode != "tls" && c.SMTP.TLSMode != "none" {
			return errors.New("SMTP_TLS_MODE must be starttls, tls, or none")
		}
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
