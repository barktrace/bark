package httpapi

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	relayRequestLimit       = 1 << 20
	relayRegistrationMaxAge = time.Minute
	relayRequestMaxAge      = 5 * time.Minute
	relayFutureSkew         = 15 * time.Second
	relayBatchLimit         = 1000
)

type relayRegistrationRequest struct {
	RelayID   string `json:"relay_id"`
	PublicKey string `json:"public_key"`
	Version   string `json:"version"`
}

type relayRegisterState struct {
	Timestamp int64  `json:"timestamp"`
	RelayID   string `json:"relay_id"`
	PublicKey string `json:"public_key"`
	Random    string `json:"rand"`
}

type relayRegistrationResponse struct {
	RelayID string `json:"relay_id"`
	Token   string `json:"token"`
	Version string `json:"version"`
}

type relayIdentity struct {
	ID        string
	PublicKey string
	Internal  bool
}

type relaySignatureHeader struct {
	Timestamp time.Time `json:"t"`
	Algorithm string    `json:"a,omitempty"`
}

func (s *Server) relayRegisterChallenge(w http.ResponseWriter, r *http.Request) {
	body, ok := readRelayBody(w, r)
	if !ok {
		return
	}
	var input relayRegistrationRequest
	if err := json.Unmarshal(body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Relay registration request")
		return
	}
	if !validRelayID(input.RelayID) || input.RelayID != r.Header.Get("X-Sentry-Relay-Id") {
		writeError(w, http.StatusBadRequest, "relay_id in payload did not match header")
		return
	}
	publicKey, err := decodeRelayPublicKey(input.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid Relay public key")
		return
	}
	if err := verifyRelaySignature(publicKey, body, r.Header.Get("X-Sentry-Relay-Signature"), time.Now().UTC(), relayRegistrationMaxAge); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Relay signature")
		return
	}
	if !validRelayVersion(input.Version) {
		writeError(w, http.StatusBadRequest, "invalid Relay version")
		return
	}
	if err := s.ensureRelayKeyAvailable(r.Context(), input.RelayID, input.PublicKey); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, err := s.relayServerSecret(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not initialize Relay registration")
		return
	}
	nonce := make([]byte, 64)
	if _, err := rand.Read(nonce); err != nil {
		writeError(w, http.StatusInternalServerError, "could not initialize Relay registration")
		return
	}
	state := relayRegisterState{
		Timestamp: time.Now().UTC().Unix(), RelayID: input.RelayID, PublicKey: input.PublicKey,
		Random: base64.RawURLEncoding.EncodeToString(nonce),
	}
	token, err := signRelayState(state, secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create Relay challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"relay_id": input.RelayID, "token": token})
}

func (s *Server) relayRegisterResponse(w http.ResponseWriter, r *http.Request) {
	body, ok := readRelayBody(w, r)
	if !ok {
		return
	}
	var input relayRegistrationResponse
	if err := json.Unmarshal(body, &input); err != nil || !validRelayID(input.RelayID) || input.Token == "" {
		writeError(w, http.StatusBadRequest, "invalid Relay registration response")
		return
	}
	if input.RelayID != r.Header.Get("X-Sentry-Relay-Id") {
		writeError(w, http.StatusBadRequest, "relay_id in payload did not match header")
		return
	}
	if !validRelayVersion(input.Version) {
		writeError(w, http.StatusBadRequest, "invalid Relay version")
		return
	}
	secret, err := s.relayServerSecret(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not validate Relay registration")
		return
	}
	state, err := unpackRelayState(input.Token, secret, time.Now().UTC(), relayRegistrationMaxAge)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired Relay challenge")
		return
	}
	if state.RelayID != input.RelayID {
		writeError(w, http.StatusBadRequest, "Relay challenge identity mismatch")
		return
	}
	publicKey, err := decodeRelayPublicKey(state.PublicKey)
	if err != nil || verifyRelaySignature(publicKey, body, r.Header.Get("X-Sentry-Relay-Signature"), time.Now().UTC(), relayRegistrationMaxAge) != nil {
		writeError(w, http.StatusBadRequest, "invalid Relay signature")
		return
	}
	if err := s.registerRelay(r.Context(), input.RelayID, state.PublicKey, normalizedRelayVersion(input.Version)); err != nil {
		if errors.Is(err, errRelayKeyConflict) {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, "could not register Relay")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"relay_id": input.RelayID})
}

func (s *Server) relayProjectConfigs(w http.ResponseWriter, r *http.Request) {
	body, _, ok := s.authenticateRelayRequest(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Get("version") != "3" {
		writeError(w, http.StatusBadRequest, "only Relay project-config version 3 is supported")
		return
	}
	var input struct {
		PublicKeys []string  `json:"publicKeys"`
		Revisions  []*string `json:"revisions"`
		FullConfig bool      `json:"fullConfig"`
		NoCache    bool      `json:"noCache"`
		Global     bool      `json:"global"`
	}
	if err := json.Unmarshal(body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Relay project-config request")
		return
	}
	if len(input.PublicKeys) > relayBatchLimit {
		writeError(w, http.StatusBadRequest, "too many Relay project keys")
		return
	}
	if len(input.Revisions) != 0 && len(input.Revisions) != len(input.PublicKeys) {
		input.Revisions = nil
	}
	configs := make(map[string]any, len(input.PublicKeys))
	unchanged := make([]string, 0)
	projects, err := s.relayProjectsByKey(r.Context(), input.PublicKeys)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load Relay project configurations")
		return
	}
	for index, key := range input.PublicKeys {
		project, exists := projects[key]
		if !exists {
			configs[key] = map[string]bool{"disabled": true}
			continue
		}
		revision := relayProjectRevision(project)
		if index < len(input.Revisions) && input.Revisions[index] != nil && *input.Revisions[index] == revision {
			unchanged = append(unchanged, key)
			continue
		}
		projectID, _ := strconv.ParseUint(project.SentryID, 10, 64)
		configs[key] = map[string]any{
			"disabled":   false,
			"projectId":  projectID,
			"slug":       project.Slug,
			"rev":        revision,
			"lastChange": relayProjectTimestamp(project.CreatedAt),
			"publicKeys": []map[string]any{{"publicKey": project.PublicKey, "numericId": projectID, "isEnabled": true}},
			"config": map[string]any{
				"allowedDomains":       []string{"*"},
				"trustedRelays":        []string{},
				"trustedRelaySettings": map[string]any{},
			},
		}
	}
	response := map[string]any{"configs": configs, "pending": []string{}, "unchanged": unchanged}
	if input.Global {
		response["global"] = map[string]any{}
		response["globalStatus"] = "ready"
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) relayPublicKeys(w http.ResponseWriter, r *http.Request) {
	body, caller, ok := s.authenticateRelayRequest(w, r)
	if !ok {
		return
	}
	var input struct {
		RelayIDs []string `json:"relay_ids"`
	}
	if err := json.Unmarshal(body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Relay public-key request")
		return
	}
	if len(input.RelayIDs) > relayBatchLimit {
		writeError(w, http.StatusBadRequest, "too many Relay IDs")
		return
	}
	legacy := make(map[string]any, len(input.RelayIDs))
	relays := make(map[string]any, len(input.RelayIDs))
	for _, relayID := range input.RelayIDs {
		legacy[relayID], relays[relayID] = nil, nil
	}
	known, err := s.relaysByID(r.Context(), input.RelayIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load Relay public keys")
		return
	}
	for relayID, item := range known {
		legacy[relayID] = item.PublicKey
		relays[relayID] = map[string]any{"publicKey": item.PublicKey, "internal": item.Internal && caller.Internal}
	}
	writeJSON(w, http.StatusOK, map[string]any{"public_keys": legacy, "relays": relays})
}

func readRelayBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, relayRequestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		writeError(w, http.StatusBadRequest, "invalid Relay request body")
		return nil, false
	}
	return body, true
}

func (s *Server) authenticateRelayRequest(w http.ResponseWriter, r *http.Request) ([]byte, relayIdentity, bool) {
	body, ok := readRelayBody(w, r)
	if !ok {
		return nil, relayIdentity{}, false
	}
	relayID := r.Header.Get("X-Sentry-Relay-Id")
	if !validRelayID(relayID) {
		writeError(w, http.StatusUnauthorized, "invalid Relay identity")
		return nil, relayIdentity{}, false
	}
	var identity relayIdentity
	var internal int
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT relay_id, public_key, is_internal FROM relays WHERE relay_id = ?`, relayID).Scan(&identity.ID, &identity.PublicKey, &internal)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusUnauthorized, "Relay is not registered")
		return nil, relayIdentity{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not authenticate Relay")
		return nil, relayIdentity{}, false
	}
	identity.Internal = internal != 0
	publicKey, err := decodeRelayPublicKey(identity.PublicKey)
	if err != nil || verifyRelaySignature(publicKey, body, r.Header.Get("X-Sentry-Relay-Signature"), time.Now().UTC(), relayRequestMaxAge) != nil {
		writeError(w, http.StatusUnauthorized, "invalid Relay signature")
		return nil, relayIdentity{}, false
	}
	_, _ = s.store.DB.ExecContext(r.Context(), `UPDATE relays SET last_seen_at = ? WHERE relay_id = ?`, time.Now().UTC().Format(time.RFC3339Nano), relayID)
	return body, identity, true
}

func decodeRelayPublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func verifyRelaySignature(publicKey ed25519.PublicKey, body []byte, encoded string, now time.Time, maxAge time.Duration) error {
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		return errors.New("invalid signature format")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid signature")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("invalid signature header")
	}
	var metadata relaySignatureHeader
	if err := json.Unmarshal(header, &metadata); err != nil || metadata.Timestamp.IsZero() {
		return errors.New("invalid signature header")
	}
	if metadata.Timestamp.After(now.Add(relayFutureSkew)) || now.Sub(metadata.Timestamp) > maxAge {
		return errors.New("expired signature")
	}
	message := make([]byte, 0, len(header)+1+len(body))
	message = append(message, header...)
	message = append(message, 0)
	message = append(message, body...)
	switch metadata.Algorithm {
	case "", "v0":
		if !ed25519.Verify(publicKey, message, signature) {
			return errors.New("invalid signature")
		}
	case "v1":
		digest := sha512.Sum512(message)
		if err := ed25519.VerifyWithOptions(publicKey, digest[:], signature, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
			return errors.New("invalid signature")
		}
	default:
		return errors.New("unsupported signature algorithm")
	}
	return nil
}

func (s *Server) relayServerSecret(ctx context.Context) ([]byte, error) {
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO relay_server_keys(id, secret) VALUES (1, ?) ON CONFLICT(id) DO NOTHING`, secret); err != nil {
		return nil, err
	}
	if err := s.store.DB.QueryRowContext(ctx, `SELECT secret FROM relay_server_keys WHERE id = 1`).Scan(&secret); err != nil {
		return nil, err
	}
	if len(secret) < 32 {
		return nil, errors.New("Relay server secret is invalid")
	}
	return secret, nil
}

func signRelayState(state relayRegisterState, secret []byte) (string, error) {
	body, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha512.New, secret)
	_, _ = mac.Write([]byte(encoded))
	return encoded + ":" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func unpackRelayState(token string, secret []byte, now time.Time, maxAge time.Duration) (relayRegisterState, error) {
	encoded, signature, ok := strings.Cut(token, ":")
	if !ok || encoded == "" || signature == "" || strings.Contains(signature, ":") {
		return relayRegisterState{}, errors.New("invalid challenge token")
	}
	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return relayRegisterState{}, err
	}
	mac := hmac.New(sha512.New, secret)
	_, _ = mac.Write([]byte(encoded))
	if !hmac.Equal(decodedSignature, mac.Sum(nil)) {
		return relayRegisterState{}, errors.New("invalid challenge signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return relayRegisterState{}, err
	}
	var state relayRegisterState
	if err := json.Unmarshal(body, &state); err != nil || !validRelayID(state.RelayID) || state.Random == "" {
		return relayRegisterState{}, errors.New("invalid challenge state")
	}
	timestamp := time.Unix(state.Timestamp, 0).UTC()
	if timestamp.After(now.Add(relayFutureSkew)) || now.Sub(timestamp) > maxAge {
		return relayRegisterState{}, errors.New("expired challenge")
	}
	return state, nil
}

var errRelayKeyConflict = errors.New("attempted to register Relay with a different identity")

func (s *Server) ensureRelayKeyAvailable(ctx context.Context, relayID, publicKey string) error {
	var existingID, existingKey string
	err := s.store.DB.QueryRowContext(ctx, `SELECT relay_id, public_key FROM relays WHERE relay_id = ? OR public_key = ? LIMIT 1`, relayID, publicKey).Scan(&existingID, &existingKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if existingID != relayID || existingKey != publicKey {
		return errRelayKeyConflict
	}
	return nil
}

func (s *Server) registerRelay(ctx context.Context, relayID, publicKey, version string) error {
	if err := s.ensureRelayKeyAvailable(ctx, relayID, publicKey); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.store.DB.ExecContext(ctx, `
		INSERT INTO relays(relay_id, public_key, version, is_internal, last_seen_at)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(relay_id) DO UPDATE SET version = excluded.version, last_seen_at = excluded.last_seen_at
	`, relayID, publicKey, version, now)
	if err != nil {
		return errRelayKeyConflict
	}
	return nil
}

func validRelayID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validRelayVersion(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '.' && character != '-' && character != '+' && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') {
			return false
		}
	}
	return true
}

func normalizedRelayVersion(value string) string {
	if value == "" {
		return "0.0.0"
	}
	return value
}

type relayProject struct {
	SentryID  string
	Slug      string
	PublicKey string
	CreatedAt string
}

func (s *Server) relayProjectsByKey(ctx context.Context, keys []string) (map[string]relayProject, error) {
	projects := make(map[string]relayProject)
	if len(keys) == 0 {
		return projects, nil
	}
	unique := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, exists := seen[key]; exists || len(key) > 64 {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, key)
	}
	if len(unique) == 0 {
		return projects, nil
	}
	placeholders := make([]string, len(unique))
	arguments := make([]any, len(unique))
	for index, key := range unique {
		placeholders[index], arguments[index] = "?", key
	}
	rows, err := s.store.DB.QueryContext(ctx, `SELECT sentry_id, slug, public_key, created_at FROM projects WHERE public_key IN (`+strings.Join(placeholders, ",")+`)`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var project relayProject
		if err := rows.Scan(&project.SentryID, &project.Slug, &project.PublicKey, &project.CreatedAt); err != nil {
			return nil, err
		}
		projects[project.PublicKey] = project
	}
	return projects, rows.Err()
}

func relayProjectRevision(project relayProject) string {
	digest := sha256.Sum256([]byte(project.SentryID + "\x00" + project.Slug + "\x00" + project.PublicKey + "\x00" + project.CreatedAt))
	return hex.EncodeToString(digest[:16])
}

func relayProjectTimestamp(value string) string {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano)
		}
	}
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func (s *Server) relaysByID(ctx context.Context, ids []string) (map[string]relayIdentity, error) {
	result := make(map[string]relayIdentity)
	if len(ids) == 0 {
		return result, nil
	}
	unique := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, exists := seen[id]; exists || !validRelayID(id) {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return result, nil
	}
	placeholders := make([]string, len(unique))
	arguments := make([]any, len(unique))
	for index, id := range unique {
		placeholders[index], arguments[index] = "?", id
	}
	rows, err := s.store.DB.QueryContext(ctx, `SELECT relay_id, public_key, is_internal FROM relays WHERE relay_id IN (`+strings.Join(placeholders, ",")+`)`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var identity relayIdentity
		var internal int
		if err := rows.Scan(&identity.ID, &identity.PublicKey, &internal); err != nil {
			return nil, err
		}
		identity.Internal = internal != 0
		result[identity.ID] = identity
	}
	return result, rows.Err()
}
