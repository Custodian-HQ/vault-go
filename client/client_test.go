package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendsTheKeyAndAnIdempotencyKeyOnPost(t *testing.T) {
	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	c, err := New("cdv_test_key", WithBaseURL(server.URL+"/"))
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Ok bool }
	if err := c.Do(context.Background(), http.MethodPost, "/customers", map[string]string{"external_ref": "u1"}, &out); err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "Bearer cdv_test_key" || len(got.Get("Idempotency-Key")) != 32 || !out.Ok {
		t.Errorf("unexpected request: %v, out %+v", got, out)
	}

	if err := c.Do(context.Background(), http.MethodPost, "/customers", nil, nil, WithIdempotencyKey("mine")); err != nil || got.Get("Idempotency-Key") != "mine" {
		t.Errorf("the caller's idempotency key must be used: %q, %v", got.Get("Idempotency-Key"), err)
	}
	if err := c.Do(context.Background(), http.MethodGet, "/customers", nil, nil); err != nil || got.Get("Idempotency-Key") != "" {
		t.Errorf("a GET must not carry an idempotency key: %q, %v", got.Get("Idempotency-Key"), err)
	}
}

func TestErrorBodiesBecomeAPIErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"type":"not_found_error","code":"customer_not_found","message":"No such customer","request_id":"abc"}}`))
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	var apiErr *APIError
	err := c.Do(context.Background(), http.MethodGet, "/customers/x", nil, nil)
	if !errors.As(err, &apiErr) || apiErr.Status != 404 || apiErr.Code != "customer_not_found" || apiErr.RequestID != "abc" {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestAnUnreadableErrorBodyStillGivesAnAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	var apiErr *APIError
	if err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil); !errors.As(err, &apiErr) || apiErr.Status != 502 {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestAnEmptyKeyIsRefused(t *testing.T) {
	if _, err := New("  "); err == nil {
		t.Error("an empty API key must be refused")
	}
}

func TestTheKeyDoesNotFollowARedirectToAnotherOrigin(t *testing.T) {
	var elsewhere, sameOriginSecond string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere = r.Header.Get("Authorization")
		w.Write([]byte(`{}`))
	}))
	defer other.Close()
	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, other.URL+"/landed", http.StatusFound)
		case "/around":
			http.Redirect(w, r, "/second", http.StatusFound)
		default:
			sameOriginSecond = r.Header.Get("Authorization")
			w.Write([]byte(`{}`))
		}
	}))
	defer home.Close()

	// Both servers listen on 127.0.0.1 with another port. Go alone would send the key, because it compares host names without the port.
	for name, c := range map[string]*Client{
		"the default client":      mustClient(t, home.URL),
		"a client you pass in":    mustClient(t, home.URL, WithHTTPClient(&http.Client{})),
		"a client with a Timeout": mustClient(t, home.URL, WithHTTPClient(&http.Client{Timeout: time.Minute})),
	} {
		elsewhere = "unset"
		if err := c.Do(context.Background(), http.MethodGet, "/away", nil, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if elsewhere != "" {
			t.Errorf("%s: the key went to another origin: %q", name, elsewhere)
		}
	}

	sameOriginSecond = ""
	if err := mustClient(t, home.URL).Do(context.Background(), http.MethodGet, "/around", nil, nil); err != nil {
		t.Fatal(err)
	}
	if sameOriginSecond != "Bearer k" {
		t.Errorf("a redirect inside the same origin must keep the key: %q", sameOriginSecond)
	}
}

func mustClient(t *testing.T, base string, opts ...Option) *Client {
	t.Helper()
	c, err := New("k", append([]Option{WithBaseURL(base)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnAuditTimeBoundKeepsItsFractionOfASecond(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("to")
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()
	to := time.Date(2026, 10, 29, 10, 0, 0, 900_000_000, time.UTC)
	if _, err := mustClient(t, server.URL).ListAuditEvents(context.Background(), ListAuditEventsParams{To: to}); err != nil {
		t.Fatal(err)
	}
	if got != "2026-10-29T10:00:00.9Z" {
		t.Errorf("to=%q, want 2026-10-29T10:00:00.9Z", got)
	}
}

func TestANilHTTPClientIsRefusedByNew(t *testing.T) {
	if _, err := New("k", WithHTTPClient(nil)); err == nil {
		t.Error("a nil HTTP client must give an error, not a panic later")
	}
}

func TestARedirectLoopStops(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer server.Close()
	err := mustClient(t, server.URL).Do(context.Background(), http.MethodGet, "/x", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "10 redirects") {
		t.Errorf("an endless redirect must end in the 10 redirects error, got %v", err)
	}
	if hits != 10 {
		t.Errorf("the server was asked %d times, want 10", hits)
	}
}

func TestAnAnswerThatIsNotJSONIsAnErrorNotAnEmptyResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>a captive portal</html>"))
	}))
	defer server.Close()
	var out struct{ Ok bool }
	err := mustClient(t, server.URL).Do(context.Background(), http.MethodGet, "/x", nil, &out)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "unparsed_response" || apiErr.Status != http.StatusOK {
		t.Errorf("an HTML answer with status 200 must give the unparsed_response error, got %v", err)
	}
}

func TestAnAnswerLargerThanTheLimitIsRefused(t *testing.T) {
	old := maxResponse
	maxResponse = 1024
	defer func() { maxResponse = old }()
	size := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"v":"` + strings.Repeat("x", size-8) + `"}`))
	}))
	defer server.Close()
	c := mustClient(t, server.URL)

	size = 1024
	var out struct{ V string }
	if err := c.Do(context.Background(), http.MethodGet, "/x", nil, &out); err != nil || len(out.V) != 1016 {
		t.Fatalf("an answer of exactly the limit: %v", err)
	}
	size = 1025
	var apiErr *APIError
	if err := c.Do(context.Background(), http.MethodGet, "/x", nil, &out); !errors.As(err, &apiErr) || apiErr.Code != "response_too_large" {
		t.Errorf("an answer one byte over the limit: %v", err)
	}
}

func TestAnErrorBodyIsReadOnlyInPart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(strings.Repeat("x", 1<<20)))
	}))
	defer server.Close()
	var apiErr *APIError
	err := mustClient(t, server.URL).Do(context.Background(), http.MethodGet, "/x", nil, nil)
	if !errors.As(err, &apiErr) || apiErr.Status != 502 || len(apiErr.Message) != maxErrorBody {
		t.Errorf("a long error body: %v", err)
	}
}

func TestACancelledContextEndsTheCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	c := mustClient(t, server.URL)
	for name, call := range map[string]func(context.Context) error{
		"Do": func(ctx context.Context) error { return c.Do(ctx, http.MethodGet, "/x", nil, nil) },
		"a download": func(ctx context.Context) error {
			body, err := c.DownloadDisclosedFile(ctx, "dsc_1", "passport", DownloadFileParams{})
			if err == nil {
				body.Close()
			}
			return err
		},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		if err := call(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestATimeoutIsATimeoutOnBothPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(time.Second):
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	c := mustClient(t, server.URL, WithHTTPClient(&http.Client{Timeout: 50 * time.Millisecond}))
	for name, call := range map[string]func() error{
		"Do": func() error { return c.Do(context.Background(), http.MethodGet, "/x", nil, nil) },
		"a download": func() error {
			body, err := c.DownloadDisclosedFile(context.Background(), "dsc_1", "passport", DownloadFileParams{})
			if err == nil {
				body.Close()
			}
			return err
		},
	} {
		err := call()
		var netErr net.Error
		if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Errorf("%s: want a deadline error with Timeout() true, got %v", name, err)
		}
	}
}

func TestAnErrorAnswerThatStallsIsATimeoutToo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("bad"))
		w.(http.Flusher).Flush()
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	c := mustClient(t, server.URL, WithHTTPClient(&http.Client{Timeout: 50 * time.Millisecond}))
	start := time.Now()
	body, err := c.DownloadDisclosedFile(context.Background(), "dsc_1", "passport", DownloadFileParams{})
	if err == nil {
		body.Close()
	}
	var netErr net.Error
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &netErr) || !netErr.Timeout() || time.Since(start) > time.Second {
		t.Errorf("want a timeout error within the limit, got %v after %v", err, time.Since(start))
	}
}

type slowTransport struct {
	wait   time.Duration
	closed *bool
}

func (s slowTransport) RoundTrip(*http.Request) (*http.Response, error) {
	time.Sleep(s.wait)
	return &http.Response{StatusCode: http.StatusOK, Body: closeFlag{strings.NewReader("late"), s.closed}}, nil
}

type closeFlag struct {
	io.Reader
	closed *bool
}

func (c closeFlag) Close() error { *c.closed = true; return nil }

func TestAnAnswerThatComesAfterTheTimerRanIsATimeout(t *testing.T) {
	closed := false
	c := mustClient(t, "https://api.example", WithHTTPClient(&http.Client{Timeout: 20 * time.Millisecond, Transport: slowTransport{wait: 80 * time.Millisecond, closed: &closed}}))
	body, err := c.DownloadDisclosedFile(context.Background(), "dsc_1", "passport", DownloadFileParams{})
	if err == nil {
		body.Close()
		t.Fatal("an answer after the timeout was accepted")
	}
	var netErr net.Error
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("got %v", err)
	}
	if !closed {
		t.Error("the late answer's body was not closed")
	}
}
