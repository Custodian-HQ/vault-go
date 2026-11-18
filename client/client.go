// Package client is the HTTP client for the Custodian Data Vault API. It handles the API key, idempotency keys and
// error bodies, and has a method for each endpoint (customers, sessions, records, disclosures, ...).
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
	"net/url"
	"strings"
	"time"
)

// maxResponse is the largest answer Do reads. It is a variable so a test can lower it.
var maxResponse int64 = 32 << 20

// maxErrorBody is the most of an error answer that is read.
const maxErrorBody = 64 << 10

// DefaultBaseURL is the vault API, with its version.
const DefaultBaseURL = "https://api.thecustodian.io/vault/v1"

const (
	defaultTimeout       = 30 * time.Second
	maxRedirects         = 10
	headerAuthorization  = "Authorization"
	headerIdempotencyKey = "Idempotency-Key"
	// errorTypeAPI is the Type of an APIError that the library makes itself.
	errorTypeAPI     = "api_error"
	codeFileReplaced = "file_replaced"
)

// Client sends requests to the API for one API key. It does not change after New, so one client can serve many goroutines.
type Client struct {
	baseURL   string
	apiKey    string
	http      *http.Client
	allowHTTP bool
}

// String hides the API key, so printing a Client (for example with %+v) does not leak it.
func (c Client) String() string { return "custodian.Client{baseURL: " + c.baseURL + "}" }

// GoString does the same for %#v.
func (c Client) GoString() string { return c.String() }

// Option changes how New makes a client.
type Option func(*Client)

// WithBaseURL points the client at another server, such as a test server.
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") } }

// WithInsecureHTTP lets the base URL use plain http for a host that is not local. The API key then travels in clear text: use it only on a trusted network.
func WithInsecureHTTP() Option { return func(c *Client) { c.allowHTTP = true } }

// WithHTTPClient replaces the HTTP client. New copies it, so later changes to h are not seen. If h has its own CheckRedirect,
// the library does not guard redirects: that function must keep the API key from other servers.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// New makes a client for an API key. The key must not be empty.
func New(apiKey string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("custodian: an API key is required")
	}
	c := &Client{baseURL: DefaultBaseURL, apiKey: apiKey, http: &http.Client{Timeout: defaultTimeout}}
	for _, opt := range opts {
		opt(c)
	}
	if c.http == nil {
		return nil, errors.New("custodian: the HTTP client must not be nil")
	}
	if err := c.checkBaseURL(); err != nil {
		return nil, err
	}
	if c.http.CheckRedirect == nil {
		h := *c.http
		h.CheckRedirect = dropKeyOnOtherOrigin
		c.http = &h
	}
	return c, nil
}

func (c *Client) checkBaseURL() error {
	u, err := url.Parse(c.baseURL)
	if err != nil || u.Host == "" {
		return errors.New("custodian: the base URL is not valid")
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && (c.allowHTTP || isLocalHost(u.Hostname())):
		return nil
	}
	return errors.New("custodian: the base URL must start with https. Plain http works only for localhost, or with WithInsecureHTTP")
}

func isLocalHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// dropKeyOnOtherOrigin refuses a redirect to another origin, so neither the API key nor a replayed POST body (307 or 308) can reach another
// server. Go compares host names only, so the scheme and the port are compared here too.
func dropKeyOnOtherOrigin(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("custodian: stopped after %d redirects", maxRedirects)
	}
	first := via[0].URL
	if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
		return errors.New("custodian: the API sent the request to another server, so the library did not follow it")
	}
	return nil
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

// Error gives the status, the code, the message and the request id, which Custodian support asks for.
func (e *APIError) Error() string {
	return fmt.Sprintf("custodian: %d %s: %s (request %s)", e.Status, e.Code, e.Message, e.RequestID)
}

// ErrFileReplaced means the customer replaced or removed a file after approving it, so the approved key no longer fits: ask the customer
// again. errors.Is matches it on the *APIError of a 410 file_replaced answer.
var ErrFileReplaced = errors.New("custodian: the customer replaced or removed the file after approving it. Ask the customer again")

// Is lets errors.Is match the sentinel errors of the package.
func (e *APIError) Is(target error) bool {
	return target == ErrFileReplaced && e.Status == http.StatusGone && e.Code == codeFileReplaced
}

// Do sends a request. body and out may be nil. A POST gets an Idempotency-Key, so a retry cannot repeat the action;
// pass your own with WithIdempotencyKey to retry across calls.
func (c *Client) Do(ctx context.Context, method, path string, body, out any, opts ...RequestOption) error {
	req, err := c.newRequest(ctx, method, path, body, opts)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		payload, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		if err != nil {
			return err
		}
		return parseError(resp.StatusCode, payload)
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) > maxResponse {
		return &APIError{Status: resp.StatusCode, Type: errorTypeAPI, Code: "response_too_large", Message: "the answer is too large to read"}
	}
	if out == nil || len(payload) == 0 {
		return nil
	}
	if !json.Valid(payload) {
		return &APIError{Status: resp.StatusCode, Type: errorTypeAPI, Code: "unparsed_response", Message: "the answer is not valid JSON"}
	}
	return json.Unmarshal(payload, out)
}

// ErrBadID means an id or name for a path is empty, ".", or "..". No real id looks like these, and they would change which endpoint runs.
var ErrBadID = errors.New("custodian: an id or name must not be empty, \".\" or \"..\"")

// badSegment marks a path that pathSegment refused. newRequest turns it into ErrBadID before anything is sent.
const badSegment = "\x00bad-id"

func pathSegment(s string) string {
	if s == "" || s == "." || s == ".." {
		return badSegment
	}
	return url.PathEscape(s)
}

func (c *Client) newRequest(ctx context.Context, method, path string, body any, opts []RequestOption) (*http.Request, error) {
	if strings.Contains(path, badSegment) {
		return nil, ErrBadID
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set(headerAuthorization, "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost {
		key, err := newIdempotencyKey()
		if err != nil {
			return nil, err
		}
		req.Header.Set(headerIdempotencyKey, key)
	}
	for _, opt := range opts {
		opt(req)
	}
	return req, nil
}

// stream sends a GET and returns the body unread when the status is one of ok. The HTTP client's timeout limits the wait for the answer
// only, not the read of the body, so a large download is not cut off; ctx limits both.
func (c *Client) stream(ctx context.Context, path string, header http.Header, ok ...int) (io.ReadCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	req, err := c.newRequest(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream, application/json")
	for k, v := range header {
		req.Header[k] = v
	}
	h := *c.http
	h.Timeout = 0
	var timer *time.Timer
	if c.http.Timeout > 0 {
		timer = time.AfterFunc(c.http.Timeout, cancel)
	}
	// Stop is false when the timer already ran, even if Do came back with an answer just before.
	fired := func() bool { return timer != nil && !timer.Stop() }
	resp, err := h.Do(req)
	if err != nil {
		timedOut := fired()
		cancel()
		if timedOut {
			return nil, &timeoutError{c.http.Timeout}
		}
		return nil, err
	}
	for _, status := range ok {
		if resp.StatusCode == status {
			if fired() {
				resp.Body.Close()
				cancel()
				return nil, &timeoutError{c.http.Timeout}
			}
			return &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}, nil
		}
	}
	defer cancel()
	defer resp.Body.Close()
	// The timer keeps running while the error body is read, so a stalled error answer times out too.
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if timedOut := fired(); err != nil {
		if timedOut {
			return nil, &timeoutError{c.http.Timeout}
		}
		return nil, err
	}
	if resp.StatusCode < 300 {
		return nil, &APIError{Status: resp.StatusCode, Type: errorTypeAPI, Code: "unexpected_status", Message: "the answer is not the one asked for"}
	}
	return nil, parseError(resp.StatusCode, payload)
}

// timeoutError is what stream returns when the answer does not come in time. It matches errors.Is(err, context.DeadlineExceeded) and
// has Timeout() true, as the error of Do does.
type timeoutError struct{ wait time.Duration }

func (e *timeoutError) Error() string   { return "custodian: no answer within " + e.wait.String() }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
func (e *timeoutError) Unwrap() error   { return context.DeadlineExceeded }

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// RequestOption changes one request.
type RequestOption func(*http.Request)

// WithIdempotencyKey sets the key yourself.
func WithIdempotencyKey(key string) RequestOption {
	return func(r *http.Request) { r.Header.Set(headerIdempotencyKey, key) }
}

func parseError(status int, payload []byte) error {
	var body struct {
		Error APIError `json:"error"`
	}
	if err := json.Unmarshal(payload, &body); err != nil || body.Error.Code == "" {
		return &APIError{Status: status, Type: errorTypeAPI, Code: "unparsed_error", Message: truncate(strings.TrimSpace(string(payload)), maxRawMessage)}
	}
	body.Error.Status = status
	return &body.Error
}

// maxRawMessage is how much of a non-JSON error answer goes into APIError.Message, which callers often log.
const maxRawMessage = 200

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

func newIdempotencyKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
