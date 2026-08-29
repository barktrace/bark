package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPTokenLifecycle(t *testing.T) {
	server, owner := permissionsFixture(t)
	create := principalRequest(t, owner, http.MethodPost, "/organizations/org/mcp-tokens", `{"name":"Claude","scopes":["read","write"],"expires_in_days":30}`)
	create.SetPathValue("organization_id", "org")
	response := httptest.NewRecorder()
	server.createMCPToken(response, create)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		ID     string   `json:"id"`
		Token  string   `json:"token"`
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, "bark_mcp_") || len(created.Scopes) != 2 {
		t.Fatalf("created token = %#v", created)
	}

	list := principalRequest(t, owner, http.MethodGet, "/organizations/org/mcp-tokens", "")
	list.SetPathValue("organization_id", "org")
	response = httptest.NewRecorder()
	server.mcpTokens(response, list)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), created.Token) {
		t.Fatalf("list status = %d body=%s", response.Code, response.Body.String())
	}

	remove := principalRequest(t, owner, http.MethodDelete, "/organizations/org/mcp-tokens/"+created.ID, "")
	remove.SetPathValue("organization_id", "org")
	remove.SetPathValue("token_id", created.ID)
	response = httptest.NewRecorder()
	server.deleteMCPToken(response, remove)
	if response.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestMCPTokenValidation(t *testing.T) {
	if scopes, ok := normalizeMCPScopes(nil); !ok || len(scopes) != 1 || scopes[0] != "read" {
		t.Fatalf("default scopes = %#v, %v", scopes, ok)
	}
	if _, ok := normalizeMCPScopes([]string{"admin"}); ok {
		t.Fatal("invalid scope accepted")
	}
}
