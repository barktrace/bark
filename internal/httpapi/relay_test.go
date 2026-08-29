package httpapi

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

func TestRelayRegistrationAndProjectConfiguration(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	server := New(configForTest(), st, &auth.Service{})
	relayID := uuid.NewString()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := base64.RawURLEncoding.EncodeToString(publicKey)

	challengeBody := mustJSON(t, relayRegistrationRequest{RelayID: relayID, PublicKey: encodedKey, Version: "25.8.0"})
	challenge := signedRelayRequest(t, http.MethodPost, "/api/0/relays/register/challenge/", relayID, challengeBody, privateKey, "v0", time.Now())
	challengeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(challengeResponse, challenge)
	if challengeResponse.Code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s", challengeResponse.Code, challengeResponse.Body.String())
	}
	var challengePayload struct {
		RelayID string `json:"relay_id"`
		Token   string `json:"token"`
	}
	if err := json.Unmarshal(challengeResponse.Body.Bytes(), &challengePayload); err != nil {
		t.Fatal(err)
	}
	if challengePayload.RelayID != relayID || challengePayload.Token == "" {
		t.Fatalf("unexpected challenge: %+v", challengePayload)
	}

	registerBody := mustJSON(t, relayRegistrationResponse{RelayID: relayID, Token: challengePayload.Token, Version: "25.8.0"})
	register := signedRelayRequest(t, http.MethodPost, "/api/0/relays/register/response/", relayID, registerBody, privateKey, "v1", time.Now())
	registerResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(registerResponse, register)
	if registerResponse.Code != http.StatusOK {
		t.Fatalf("registration status=%d body=%s", registerResponse.Code, registerResponse.Body.String())
	}
	var storedKey, version string
	var internal int
	if err := st.DB.QueryRow(`SELECT public_key, version, is_internal FROM relays WHERE relay_id = ?`, relayID).Scan(&storedKey, &version, &internal); err != nil {
		t.Fatal(err)
	}
	if storedKey != encodedKey || version != "25.8.0" || internal != 1 {
		t.Fatalf("stored Relay key=%q version=%q internal=%d", storedKey, version, internal)
	}

	if _, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'acme', 'Acme');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key, created_at)
		VALUES ('project', '42', 'org', 'checkout', 'Checkout', 'project-key', '2026-08-29 16:00:00');
	`); err != nil {
		t.Fatal(err)
	}
	configBody := []byte(`{"publicKeys":["project-key","unknown-key"],"revisions":[null,null],"fullConfig":true,"global":true}`)
	configRequest := signedRelayRequest(t, http.MethodPost, "/api/0/relays/projectconfigs/?version=3", relayID, configBody, privateKey, "v1", time.Now())
	configResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(configResponse, configRequest)
	if configResponse.Code != http.StatusOK {
		t.Fatalf("project config status=%d body=%s", configResponse.Code, configResponse.Body.String())
	}
	var configPayload struct {
		Configs map[string]struct {
			Disabled  bool   `json:"disabled"`
			ProjectID uint64 `json:"projectId"`
			Slug      string `json:"slug"`
			Revision  string `json:"rev"`
		} `json:"configs"`
		Unchanged   []string       `json:"unchanged"`
		Global      map[string]any `json:"global"`
		GlobalState string         `json:"globalStatus"`
	}
	if err := json.Unmarshal(configResponse.Body.Bytes(), &configPayload); err != nil {
		t.Fatal(err)
	}
	project := configPayload.Configs["project-key"]
	if project.Disabled || project.ProjectID != 42 || project.Slug != "checkout" || project.Revision == "" {
		t.Fatalf("unexpected project config: %+v", project)
	}
	if !configPayload.Configs["unknown-key"].Disabled || configPayload.GlobalState != "ready" || configPayload.Global == nil {
		t.Fatalf("unexpected project-config envelope: %+v", configPayload)
	}

	revisionBody := mustJSON(t, map[string]any{"publicKeys": []string{"project-key"}, "revisions": []string{project.Revision}})
	revisionRequest := signedRelayRequest(t, http.MethodPost, "/api/0/relays/projectconfigs/?version=3", relayID, revisionBody, privateKey, "v0", time.Now())
	revisionResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(revisionResponse, revisionRequest)
	if revisionResponse.Code != http.StatusOK {
		t.Fatalf("revision status=%d body=%s", revisionResponse.Code, revisionResponse.Body.String())
	}
	var revisionPayload struct {
		Configs   map[string]any `json:"configs"`
		Unchanged []string       `json:"unchanged"`
	}
	if err := json.Unmarshal(revisionResponse.Body.Bytes(), &revisionPayload); err != nil {
		t.Fatal(err)
	}
	if len(revisionPayload.Configs) != 0 || len(revisionPayload.Unchanged) != 1 || revisionPayload.Unchanged[0] != "project-key" {
		t.Fatalf("unexpected unchanged response: %+v", revisionPayload)
	}

	keysBody := mustJSON(t, map[string]any{"relay_ids": []string{relayID, uuid.NewString()}})
	keysRequest := signedRelayRequest(t, http.MethodPost, "/api/0/relays/publickeys/", relayID, keysBody, privateKey, "v1", time.Now())
	keysResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(keysResponse, keysRequest)
	if keysResponse.Code != http.StatusOK {
		t.Fatalf("public keys status=%d body=%s", keysResponse.Code, keysResponse.Body.String())
	}
	var keysPayload struct {
		PublicKeys map[string]*string `json:"public_keys"`
		Relays     map[string]*struct {
			PublicKey string `json:"publicKey"`
			Internal  bool   `json:"internal"`
		} `json:"relays"`
	}
	if err := json.Unmarshal(keysResponse.Body.Bytes(), &keysPayload); err != nil {
		t.Fatal(err)
	}
	if keysPayload.PublicKeys[relayID] == nil || *keysPayload.PublicKeys[relayID] != encodedKey || keysPayload.Relays[relayID] == nil || !keysPayload.Relays[relayID].Internal {
		t.Fatalf("unexpected public-key response: %+v", keysPayload)
	}
}

func TestRelayAuthenticationRejectsTamperingAndExpiredSignatures(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	server := New(configForTest(), st, &auth.Service{})
	relayID := uuid.NewString()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := base64.RawURLEncoding.EncodeToString(publicKey)
	if _, err := st.DB.Exec(`INSERT INTO relays(relay_id, public_key, version) VALUES (?, ?, '25.8.0')`, relayID, encodedKey); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"publicKeys":[]}`)

	expired := signedRelayRequest(t, http.MethodPost, "/api/0/relays/projectconfigs/?version=3", relayID, body, privateKey, "v0", time.Now().Add(-relayRequestMaxAge-time.Second))
	expiredResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(expiredResponse, expired)
	if expiredResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expired signature status=%d body=%s", expiredResponse.Code, expiredResponse.Body.String())
	}

	tampered := signedRelayRequest(t, http.MethodPost, "/api/0/relays/projectconfigs/?version=3", relayID, body, privateKey, "v1", time.Now())
	tampered.Body = io.NopCloser(bytes.NewReader([]byte(`{"publicKeys":["tampered"]}`)))
	tamperedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(tamperedResponse, tampered)
	if tamperedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("tampered signature status=%d body=%s", tamperedResponse.Code, tamperedResponse.Body.String())
	}
}

func TestRelayRegistrationRejectsIdentityKeyReplacement(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	server := New(configForTest(), st, &auth.Service{})
	relayID := uuid.NewString()
	firstPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO relays(relay_id, public_key, version) VALUES (?, ?, '25.8.0')`, relayID, base64.RawURLEncoding.EncodeToString(firstPublicKey)); err != nil {
		t.Fatal(err)
	}
	secondPublicKey, secondPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON(t, relayRegistrationRequest{RelayID: relayID, PublicKey: base64.RawURLEncoding.EncodeToString(secondPublicKey), Version: "25.8.0"})
	request := signedRelayRequest(t, http.MethodPost, "/api/0/relays/register/challenge/", relayID, body, secondPrivateKey, "v0", time.Now())
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("replacement status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRelayLivenessDoesNotRequireAuthentication(t *testing.T) {
	t.Parallel()
	server := New(configForTest(), openTestStore(t), &auth.Service{})
	request := httptest.NewRequest(http.MethodGet, "/api/0/relays/live/", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "{\"is_healthy\":true}\n" {
		t.Fatalf("liveness status=%d body=%s", response.Code, response.Body.String())
	}
}

func signedRelayRequest(t *testing.T, method, target, relayID string, body []byte, privateKey ed25519.PrivateKey, algorithm string, timestamp time.Time) *http.Request {
	t.Helper()
	header, err := json.Marshal(relaySignatureHeader{Timestamp: timestamp.UTC(), Algorithm: algorithm})
	if err != nil {
		t.Fatal(err)
	}
	message := append(append(append(make([]byte, 0, len(header)+1+len(body)), header...), 0), body...)
	var signature []byte
	switch algorithm {
	case "v1":
		digest := sha512.Sum512(message)
		signature, err = privateKey.Sign(rand.Reader, digest[:], &ed25519.Options{Hash: crypto.SHA512})
	default:
		signature = ed25519.Sign(privateKey, message)
	}
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Sentry-Relay-Id", relayID)
	request.Header.Set("X-Sentry-Relay-Signature", base64.RawURLEncoding.EncodeToString(signature)+"."+base64.RawURLEncoding.EncodeToString(header))
	return request
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
