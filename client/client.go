// Package client is the HTTP client for the Custodian Data Vault API. It handles the API key, idempotency keys and
// error bodies. The endpoint methods (customers, sessions, records, ...) are added with the API in Phase 1.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the vault API, with its version.
const DefaultBaseURL = "https://api.thecustodian.io/vault/v1"

type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

type Option func(*Client)

// WithBaseURL points the client at another server, such as a test server.
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") } }

// WithHTTPClient replaces the HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// New makes a client for an API key. The key must not be empty.
func New(apiKey string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("custodian: an API key is required")
	}
	c := &Client{baseURL: DefaultBaseURL, apiKey: apiKey, http: &http.Client{Timeout: 30 * time.Second}}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// APIError is the error body of the API: {"error": {...}}.
type APIError struct {
	Status    int    `json:"-"`
	Type      string `json:"type"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Param     string `json:"param,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("custodian: %d %s: %s (request %s)", e.Status, e.Code, e.Message, e.RequestID)
}

// Do sends a request. body and out may be nil. A POST gets an Idempotency-Key, so a retry cannot repeat the action;
// pass your own with WithIdempotencyKey to retry across calls.
func (c *Client) Do(ctx context.Context, method, path string, body, out any, opts ...RequestOption) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost {
		key, err := newIdempotencyKey()
		if err != nil {
			return err
		}
		req.Header.Set("Idempotency-Key", key)
	}
	for _, opt := range opts {
		opt(req)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return parseError(resp.StatusCode, payload)
	}
	if out == nil || len(payload) == 0 {
		return nil
	}
	return json.Unmarshal(payload, out)
}

// RequestOption changes one request.
type RequestOption func(*http.Request)

// WithIdempotencyKey sets the key yourself.
func WithIdempotencyKey(key string) RequestOption {
	return func(r *http.Request) { r.Header.Set("Idempotency-Key", key) }
}

func parseError(status int, payload []byte) error {
	var body struct {
		Error APIError `json:"error"`
	}
	if err := json.Unmarshal(payload, &body); err != nil || body.Error.Code == "" {
		return &APIError{Status: status, Type: "api_error", Code: "unparsed_error", Message: strings.TrimSpace(string(payload))}
	}
	body.Error.Status = status
	return &body.Error
}

func newIdempotencyKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
