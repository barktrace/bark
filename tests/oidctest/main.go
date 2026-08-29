// Command oidctest is a deliberately small OpenID Connect provider used only
// by Barktrace's end-to-end tests. It performs an immediate login as a fixed,
// verified user and validates authorization-code PKCE exchanges.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type authorization struct {
	clientID      string
	redirectURI   string
	nonce         string
	codeChallenge string
	expiresAt     time.Time
}

type provider struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string
	key          *rsa.PrivateKey
	mu           sync.Mutex
	codes        map[string]authorization
}

func main() {
	issuer := env("OIDC_TEST_ISSUER", "http://127.0.0.1:19090")
	p := &provider{
		issuer:       strings.TrimRight(issuer, "/"),
		clientID:     env("OIDC_TEST_CLIENT_ID", "barktrace-e2e"),
		clientSecret: env("OIDC_TEST_CLIENT_SECRET", "barktrace-e2e-secret"),
		redirectURI:  env("OIDC_TEST_REDIRECT_URL", "http://127.0.0.1:18080/auth/oidc/callback"),
		codes:        make(map[string]authorization),
	}
	var err error
	p.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	address := env("OIDC_TEST_ADDR", "127.0.0.1:19090")
	log.Printf("test OIDC provider listening on %s", address)
	log.Fatal(http.ListenAndServe(address, mux))
}

func (p *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/authorize",
		"token_endpoint":                        p.issuer + "/token",
		"jwks_uri":                              p.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "name", "picture", "nonce"},
	})
}

func (p *provider) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Get("response_type") != "code" || query.Get("client_id") != p.clientID || query.Get("redirect_uri") != p.redirectURI || query.Get("state") == "" || query.Get("nonce") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		http.Error(w, "PKCE S256 is required", http.StatusBadRequest)
		return
	}
	code, err := randomToken(24)
	if err != nil {
		http.Error(w, "could not create code", http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	p.codes[code] = authorization{
		clientID:      p.clientID,
		redirectURI:   p.redirectURI,
		nonce:         query.Get("nonce"),
		codeChallenge: query.Get("code_challenge"),
		expiresAt:     time.Now().Add(time.Minute),
	}
	p.mu.Unlock()
	destination, _ := url.Parse(p.redirectURI)
	values := destination.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	destination.RawQuery = values.Encode()
	http.Redirect(w, r, destination.String(), http.StatusFound)
}

func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID, clientSecret = r.Form.Get("client_id"), r.Form.Get("client_secret")
	}
	if clientID != p.clientID || clientSecret != p.clientSecret {
		oauthError(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		oauthError(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")
	p.mu.Lock()
	authorization, exists := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !exists || time.Now().After(authorization.expiresAt) || authorization.clientID != clientID || authorization.redirectURI != r.Form.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(challenge[:]) != authorization.codeChallenge {
		oauthError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	now := time.Now()
	idToken, err := p.sign(map[string]any{
		"iss": p.issuer, "sub": "barktrace-e2e-user", "aud": p.clientID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": authorization.nonce,
		"email": "e2e@barktrace.test", "email_verified": true, "name": "Barktrace E2E",
	})
	if err != nil {
		oauthError(w, "server_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "e2e-access-token", "token_type": "Bearer", "expires_in": 300, "id_token": idToken,
	})
}

func (p *provider) jwks(w http.ResponseWriter, _ *http.Request) {
	e := big.NewInt(int64(p.key.PublicKey.E)).Bytes()
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "barktrace-e2e", "n": base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e),
	}}})
}

func (p *provider) sign(claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "barktrace-e2e", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func oauthError(w http.ResponseWriter, code string, status int) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
