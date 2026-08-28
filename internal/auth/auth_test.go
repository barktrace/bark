package auth

import (
	"net/http"
	"net/url"
	"testing"
)

func TestSafeReturnTo(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"":                               "/ui/",
		"/ui/":                           "/ui/",
		"/ui/issues?project=one":         "/ui/issues?project=one",
		"/ui-pretending-to-be-ui":        "/ui/",
		"/api/0/organizations":           "/ui/",
		"https://attacker.example/ui/":   "/ui/",
		"//attacker.example/ui/redirect": "/ui/",
	}
	for input, want := range tests {
		if got := safeReturnTo(input); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHTTPSOnlyTransport(t *testing.T) {
	t.Parallel()

	recorder := &recordingTransport{}
	transport := &httpsOnlyTransport{base: recorder, allowLoopbackHTTP: true}

	for _, raw := range []string{"https://id.example/token", "http://localhost:1411/token", "http://127.0.0.1/token", "http://[::1]/token"} {
		request := &http.Request{Method: http.MethodGet, URL: mustURL(t, raw)}
		if _, err := transport.RoundTrip(request); err != nil {
			t.Errorf("RoundTrip(%q): %v", raw, err)
		}
	}
	for _, raw := range []string{"http://id.example/token", "http://localhost.evil.example/token", "ftp://id.example/token"} {
		request := &http.Request{Method: http.MethodGet, URL: mustURL(t, raw)}
		if _, err := transport.RoundTrip(request); err == nil {
			t.Errorf("RoundTrip(%q) unexpectedly succeeded", raw)
		}
	}
	if recorder.calls != 4 {
		t.Fatalf("base transport calls = %d, want 4", recorder.calls)
	}
}

func TestHTTPSIssuerDoesNotPermitLoopbackHTTPEndpoints(t *testing.T) {
	t.Parallel()
	if err := validateEndpoint("http://localhost/token", isLoopbackHTTP("https://id.example")); err == nil {
		t.Fatal("HTTPS issuer allowed an HTTP loopback endpoint")
	}
}

type recordingTransport struct{ calls int }

func (r *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.calls++
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: request}, nil
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
