package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesUIAndSPAFallback(t *testing.T) {
	t.Parallel()
	handler := Handler()
	for _, target := range []string{"/ui/", "/ui/login/", "/ui/issues/not-found"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("GET %s status = %d", target, response.Code)
		}
		if !strings.Contains(strings.ToLower(response.Body.String()), "<!doctype html>") {
			t.Errorf("GET %s did not serve HTML", target)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/ui/app.js", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "routeMeta") {
		t.Fatalf("app asset response = %d, body did not contain application script", response.Code)
	}
}
