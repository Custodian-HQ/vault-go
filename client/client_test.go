package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
