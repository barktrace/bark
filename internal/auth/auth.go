package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/config"
	"github.com/GhaziBenDahmane/barktrace/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "barktrace_session"
	stateCookie   = "barktrace_oidc_state"
)

type Service struct {
	cfg      config.Config
	store    *store.Store
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	client   *http.Client
}

type Principal struct {
	UserID      string       `json:"id"`
	Email       string       `json:"email"`
	Name        string       `json:"name"`
	AvatarURL   string       `json:"avatar_url,omitempty"`
	Memberships []Membership `json:"memberships"`
}

type Membership struct {
	OrganizationID   string `json:"organization_id"`
	OrganizationSlug string `json:"organization_slug"`
	OrganizationName string `json:"organization_name"`
	Role             string `json:"role"`
}

type claims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func New(ctx context.Context, cfg config.Config, st *store.Store) (*Service, error) {
	allowLoopbackHTTP := isLoopbackHTTP(cfg.OIDC.IssuerURL)
	client := &http.Client{
		Transport: &httpsOnlyTransport{
			base:              http.DefaultTransport,
			allowLoopbackHTTP: allowLoopbackHTTP,
		},
		Timeout: 15 * time.Second,
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.OIDC.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	if err := validateEndpoint(endpoint.AuthURL, allowLoopbackHTTP); err != nil {
		return nil, fmt.Errorf("validate OIDC authorization endpoint: %w", err)
	}
	if err := validateEndpoint(endpoint.TokenURL, allowLoopbackHTTP); err != nil {
		return nil, fmt.Errorf("validate OIDC token endpoint: %w", err)
	}
	oauthCfg := oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  cfg.OIDC.RedirectURL,
		Scopes:       cfg.OIDC.Scopes,
	}
	return &Service{
		cfg:      cfg,
		store:    st,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID}),
		oauth:    oauthCfg,
		client:   client,
	}, nil
}

func (s *Service) ProviderName() string { return s.cfg.OIDC.ProviderName }

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start login")
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start login")
		return
	}
	verifier := oauth2.GenerateVerifier()
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	expires := time.Now().UTC().Add(10 * time.Minute)
	if _, err := s.store.DB.ExecContext(r.Context(), `
		INSERT INTO oidc_requests(state_hash, nonce, pkce_verifier, return_to, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, tokenHash(state), nonce, verifier, returnTo, expires.Format(time.RFC3339Nano)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not persist login request")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     "/auth/oidc/callback",
		Expires:  expires,
		MaxAge:   600,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	destination := s.oauth.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
	)
	http.Redirect(w, r, destination, http.StatusFound)
}

func (s *Service) Callback(w http.ResponseWriter, r *http.Request) {
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		redirectLoginError(w, r, providerError)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	cookie, err := r.Cookie(stateCookie)
	if err != nil || state == "" || code == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		redirectLoginError(w, r, "invalid_state")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth/oidc/callback", MaxAge: -1, HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteLaxMode})

	var nonce, verifier, returnTo, expiresRaw string
	err = s.store.DB.QueryRowContext(r.Context(), `
		DELETE FROM oidc_requests
		WHERE state_hash = ?
		RETURNING nonce, pkce_verifier, return_to, expires_at
	`, tokenHash(state)).Scan(&nonce, &verifier, &returnTo, &expiresRaw)
	if err != nil {
		redirectLoginError(w, r, "expired_state")
		return
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil || time.Now().After(expires) {
		redirectLoginError(w, r, "expired_state")
		return
	}
	requestContext := oidc.ClientContext(r.Context(), s.client)
	token, err := s.oauth.Exchange(requestContext, code, oauth2.VerifierOption(verifier))
	if err != nil {
		redirectLoginError(w, r, "exchange_failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		redirectLoginError(w, r, "missing_id_token")
		return
	}
	idToken, err := s.verifier.Verify(requestContext, rawIDToken)
	if err != nil {
		redirectLoginError(w, r, "invalid_id_token")
		return
	}
	if idToken.Nonce != nonce {
		redirectLoginError(w, r, "invalid_nonce")
		return
	}
	var identity claims
	if err := idToken.Claims(&identity); err != nil {
		redirectLoginError(w, r, "invalid_claims")
		return
	}
	identity.Email = strings.ToLower(strings.TrimSpace(identity.Email))
	if identity.Subject == "" || identity.Email == "" {
		redirectLoginError(w, r, "identity_incomplete")
		return
	}
	if s.cfg.OIDC.RequireEmailVerified && !identity.EmailVerified {
		redirectLoginError(w, r, "email_not_verified")
		return
	}
	userID, err := s.findOrProvision(r.Context(), idToken.Issuer, identity)
	if err != nil {
		redirectLoginError(w, r, "provisioning_failed")
		return
	}
	plainSession, err := randomToken(32)
	if err != nil {
		redirectLoginError(w, r, "session_failed")
		return
	}
	sessionExpires := time.Now().UTC().Add(s.cfg.SessionLifetime)
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)`, tokenHash(plainSession), userID, sessionExpires.Format(time.RFC3339Nano)); err != nil {
		redirectLoginError(w, r, "session_failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    plainSession,
		Path:     "/",
		Expires:  sessionExpires,
		MaxAge:   int(s.cfg.SessionLifetime.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_, _ = s.store.DB.ExecContext(r.Context(), `DELETE FROM sessions WHERE token_hash = ?`, tokenHash(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) Authenticate(r *http.Request) (*Principal, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, err
	}
	var principal Principal
	var expiresRaw string
	err = s.store.DB.QueryRowContext(r.Context(), `
		SELECT u.id, u.email, u.name, COALESCE(u.avatar_url, ''), s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ?
	`, tokenHash(cookie.Value)).Scan(&principal.UserID, &principal.Email, &principal.Name, &principal.AvatarURL, &expiresRaw)
	if err != nil {
		return nil, err
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil || time.Now().After(expires) {
		_, _ = s.store.DB.ExecContext(r.Context(), `DELETE FROM sessions WHERE token_hash = ?`, tokenHash(cookie.Value))
		return nil, errors.New("session expired")
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT o.id, o.slug, o.name, m.role
		FROM organization_memberships m JOIN organizations o ON o.id = m.organization_id
		WHERE m.user_id = ? ORDER BY o.name
	`, principal.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var membership Membership
		if err := rows.Scan(&membership.OrganizationID, &membership.OrganizationSlug, &membership.OrganizationName, &membership.Role); err != nil {
			return nil, err
		}
		principal.Memberships = append(principal.Memberships, membership)
	}
	return &principal, rows.Err()
}

func (s *Service) findOrProvision(ctx context.Context, issuer string, identity claims) (string, error) {
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var userID string
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM oidc_identities WHERE issuer = ? AND subject = ?`, issuer, identity.Subject).Scan(&userID)
	if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE users SET last_login_at = CURRENT_TIMESTAMP, name = CASE WHEN ? <> '' THEN ? ELSE name END, avatar_url = CASE WHEN ? <> '' THEN ? ELSE avatar_url END WHERE id = ?`, identity.Name, identity.Name, identity.Picture, identity.Picture, userID)
		if err != nil {
			return "", err
		}
		return userID, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ? COLLATE NOCASE`, identity.Email).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		if !s.cfg.AutoProvision {
			return "", errors.New("automatic provisioning is disabled")
		}
		userID = uuid.NewString()
		if _, err := tx.ExecContext(ctx, `INSERT INTO users(id, email, name, avatar_url, last_login_at) VALUES (?, ?, ?, NULLIF(?, ''), CURRENT_TIMESTAMP)`, userID, identity.Email, identity.Name, identity.Picture); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oidc_identities(issuer, subject, user_id, email_at_link) VALUES (?, ?, ?, ?)`, issuer, identity.Subject, userID, identity.Email); err != nil {
		return "", err
	}
	orgID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO organizations(id, slug, name) VALUES (?, ?, ?) ON CONFLICT(slug) DO NOTHING`, orgID, s.cfg.DefaultOrgSlug, s.cfg.DefaultOrgName); err != nil {
		return "", err
	}
	if err := tx.QueryRowContext(ctx, `SELECT id FROM organizations WHERE slug = ?`, s.cfg.DefaultOrgSlug).Scan(&orgID); err != nil {
		return "", err
	}
	var memberCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM organization_memberships WHERE organization_id = ?`, orgID).Scan(&memberCount); err != nil {
		return "", err
	}
	role := "member"
	if memberCount == 0 {
		role = "owner"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO organization_memberships(organization_id, user_id, role) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, orgID, userID, role); err != nil {
		return "", err
	}
	return userID, tx.Commit()
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func safeReturnTo(candidate string) string {
	if candidate == "" {
		return "/ui/"
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || (parsed.Path != "/ui" && !strings.HasPrefix(parsed.Path, "/ui/")) {
		return "/ui/"
	}
	return parsed.RequestURI()
}

type httpsOnlyTransport struct {
	base              http.RoundTripper
	allowLoopbackHTTP bool
}

func (t *httpsOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := validateEndpoint(request.URL.String(), t.allowLoopbackHTTP); err != nil {
		return nil, err
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(request)
}

func validateEndpoint(raw string, allowLoopbackHTTP bool) error {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" {
		return errors.New("endpoint is not a valid absolute URL")
	}
	if strings.EqualFold(endpoint.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(endpoint.Scheme, "http") && allowLoopbackHTTP && isLoopbackHost(endpoint.Hostname()) {
		return nil
	}
	return errors.New("endpoint must use HTTPS")
}

func isLoopbackHTTP(raw string) bool {
	endpoint, err := url.Parse(raw)
	return err == nil && strings.EqualFold(endpoint.Scheme, "http") && isLoopbackHost(endpoint.Hostname())
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func redirectLoginError(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/ui/login/?error="+url.QueryEscape(code), http.StatusFound)
}

func writeError(w http.ResponseWriter, status int, message string) {
	http.Error(w, message, status)
}
