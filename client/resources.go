package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// call sends a request and reads the answer into T.
func call[T any](ctx context.Context, c *Client, method, path string, body any, opts ...RequestOption) (*T, error) {
	var out T
	if err := c.Do(ctx, method, path, body, &out, opts...); err != nil {
		return nil, err
	}
	return &out, nil
}

func query(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	return "?" + values.Encode()
}

func addInt(values url.Values, key string, n int) {
	if n > 0 {
		values.Set(key, strconv.Itoa(n))
	}
}

// Me says which organization and mode the API key belongs to.
type Me struct {
	Organization string `json:"organization"`
	Name         string `json:"name"`
	Livemode     bool   `json:"livemode"`
}

func (c *Client) Me(ctx context.Context) (*Me, error) {
	return call[Me](ctx, c, http.MethodGet, "/me", nil)
}

// Customer is a person who keeps data in your vault.
type Customer struct {
	ID          string `json:"id"`
	ExternalRef string `json:"external_ref"`
	Livemode    bool   `json:"livemode"`
	State       string `json:"state"`
	Enrolled    bool   `json:"enrolled"`
	// VaultSignKey is the customer's public signing key, base64url. Keep the one you got in the customer.enrolled webhook and check envelopes
	// against that one; do not rely on this field alone.
	VaultSignKey string `json:"vault_sign_key,omitempty"`
	// FirstName and LastName are the name you offered, until the customer confirms or corrects it at enrolment (NameConfirmed). After that you
	// cannot change it.
	FirstName     string    `json:"first_name,omitempty"`
	LastName      string    `json:"last_name,omitempty"`
	NameConfirmed bool      `json:"name_confirmed"`
	CreatedAt     time.Time `json:"created_at"`
}

type CustomerPage struct {
	Data    []Customer `json:"data"`
	HasMore bool       `json:"has_more"`
}

// ListCustomersParams narrows and pages the list. StartingAfter is the id of the last customer of the previous page.
type ListCustomersParams struct {
	Limit         int
	StartingAfter string
	ExternalRef   string
}

// CreateCustomer makes a customer. Pass WithIdempotencyKey to make a retry safe.
func (c *Client) CreateCustomer(ctx context.Context, externalRef string, opts ...RequestOption) (*Customer, error) {
	return call[Customer](ctx, c, http.MethodPost, "/customers", map[string]string{"external_ref": externalRef}, opts...)
}

// CreateCustomerNamed makes a customer with the name you offer for them (1 to 60 characters each). The customer confirms or corrects the name on the
// enrolment screen, and after that you cannot change it.
func (c *Client) CreateCustomerNamed(ctx context.Context, externalRef, firstName, lastName string, opts ...RequestOption) (*Customer, error) {
	return call[Customer](ctx, c, http.MethodPost, "/customers", map[string]string{"external_ref": externalRef, "first_name": firstName, "last_name": lastName}, opts...)
}

func (c *Client) GetCustomer(ctx context.Context, id string) (*Customer, error) {
	return call[Customer](ctx, c, http.MethodGet, "/customers/"+url.PathEscape(id), nil)
}

// DeleteCustomer deletes the customer and all their data at once. It cannot be undone, and the customer is not asked.
func (c *Client) DeleteCustomer(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/customers/"+url.PathEscape(id), nil, nil)
}

// ResetCustomer starts a reset of a customer who has lost every way in. Nothing is deleted until the customer confirms on the page at the
// URL in the answer. Then all their data is deleted for good, and they enrol again.
func (c *Client) ResetCustomer(ctx context.Context, id, returnURL, state string, opts ...RequestOption) (*Session, error) {
	return call[Session](ctx, c, http.MethodPost, "/customers/"+url.PathEscape(id)+"/reset", map[string]string{"return_url": returnURL, "state": state}, opts...)
}

func (c *Client) ListCustomers(ctx context.Context, p ListCustomersParams) (*CustomerPage, error) {
	values := url.Values{}
	addInt(values, "limit", p.Limit)
	if p.StartingAfter != "" {
		values.Set("starting_after", p.StartingAfter)
	}
	if p.ExternalRef != "" {
		values.Set("external_ref", p.ExternalRef)
	}
	return call[CustomerPage](ctx, c, http.MethodGet, "/customers"+query(values), nil)
}

// Key is one field you ask a customer for.
type Key struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	Type  string `json:"type,omitempty"`
	// MaxSize is the largest file for this key, in bytes. Only a file key may set it. Leave it at 0 to use your plan's limit; it cannot be larger.
	MaxSize int64 `json:"max_size,omitempty"`
	// Accept lists the file types this key takes, as MIME types ("application/pdf", "image/jpeg", "image/png"). Only a file key may set it.
	// Leave it empty to take every type the server allows.
	Accept []string `json:"accept,omitempty"`
}

// CreateSessionParams starts a visit. ReturnURL must be one you registered for the key's mode. State is required: pass a value
// you can tie to your signed-in user, and check it when the customer returns (see ParseReturn).
type CreateSessionParams struct {
	Customer  string `json:"customer"`
	Purpose   string `json:"purpose"`
	ReturnURL string `json:"return_url"`
	State     string `json:"state"`
	Template  string `json:"template,omitempty"`
	Keys      []Key  `json:"keys,omitempty"`
	// Record is the record token. A view needs it. An entry may name one to add keys to that record.
	Record     string `json:"record,omitempty"`
	Disclosure string `json:"disclosure,omitempty"`
}

// Session is one visit of a customer to the vault. URL is only set by CreateSession.
type Session struct {
	ID          string     `json:"id"`
	Customer    string     `json:"customer"`
	Purpose     string     `json:"purpose"`
	Status      string     `json:"status"`
	Livemode    bool       `json:"livemode"`
	ReturnURL   string     `json:"return_url"`
	State       string     `json:"state"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	CancelledAt *time.Time `json:"cancelled_at,omitempty"`
	// Record is the record this visit added to or shows. For an entry that makes a new record, it is set once the customer saved.
	Record   string   `json:"record,omitempty"`
	URL      string   `json:"url,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// CreateSession starts a session. Send the customer to the URL in the answer: it is shown once. Pass WithIdempotencyKey to make a retry safe.
func (c *Client) CreateSession(ctx context.Context, p CreateSessionParams, opts ...RequestOption) (*Session, error) {
	return call[Session](ctx, c, http.MethodPost, "/sessions", p, opts...)
}

// GetSession reads where a visit stands. Use it, or a webhook, to learn the result after the customer returns: never trust the
// address they come back to.
func (c *Client) GetSession(ctx context.Context, id string) (*Session, error) {
	return call[Session](ctx, c, http.MethodGet, "/sessions/"+url.PathEscape(id), nil)
}

// Template is a named list of keys.
type Template struct {
	Name     string   `json:"name"`
	Keys     []Key    `json:"keys"`
	Warnings []string `json:"warnings,omitempty"`
}

func (c *Client) ListTemplates(ctx context.Context) ([]Template, error) {
	page, err := call[struct {
		Data []Template `json:"data"`
	}](ctx, c, http.MethodGet, "/templates", nil)
	if err != nil {
		return nil, err
	}
	return page.Data, nil
}

func (c *Client) CreateTemplate(ctx context.Context, t Template) (*Template, error) {
	return call[Template](ctx, c, http.MethodPost, "/templates", t)
}

func (c *Client) GetTemplate(ctx context.Context, name string) (*Template, error) {
	return call[Template](ctx, c, http.MethodGet, "/templates/"+url.PathEscape(name), nil)
}

func (c *Client) ReplaceTemplate(ctx context.Context, name string, keys []Key) (*Template, error) {
	return call[Template](ctx, c, http.MethodPut, "/templates/"+url.PathEscape(name), map[string]any{"keys": keys})
}

func (c *Client) DeleteTemplate(ctx context.Context, name string) error {
	return c.Do(ctx, http.MethodDelete, "/templates/"+url.PathEscape(name), nil, nil)
}

// RecoveryPolicy is how many holders are needed to recover a customer's vault.
type RecoveryPolicy struct {
	RecoveryThreshold int `json:"recovery_threshold"`
}

func (c *Client) GetRecoveryPolicy(ctx context.Context) (*RecoveryPolicy, error) {
	return call[RecoveryPolicy](ctx, c, http.MethodGet, "/recovery-policy", nil)
}

func (c *Client) SetRecoveryPolicy(ctx context.Context, threshold int) (*RecoveryPolicy, error) {
	return call[RecoveryPolicy](ctx, c, http.MethodPut, "/recovery-policy", RecoveryPolicy{RecoveryThreshold: threshold})
}

// WebhookEndpoint is a receiver. Secret is only set when the endpoint is made or its secret is rotated: store it then.
type WebhookEndpoint struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	Livemode  bool      `json:"livemode"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	Secret    string    `json:"secret,omitempty"`
}

func (c *Client) CreateWebhookEndpoint(ctx context.Context, endpointURL string, events []string, opts ...RequestOption) (*WebhookEndpoint, error) {
	return call[WebhookEndpoint](ctx, c, http.MethodPost, "/webhook-endpoints", map[string]any{"url": endpointURL, "events": events}, opts...)
}

func (c *Client) ListWebhookEndpoints(ctx context.Context) ([]WebhookEndpoint, error) {
	page, err := call[struct {
		Data []WebhookEndpoint `json:"data"`
	}](ctx, c, http.MethodGet, "/webhook-endpoints", nil)
	if err != nil {
		return nil, err
	}
	return page.Data, nil
}

// WebhookEndpointUpdate says what to change. A nil or empty field stays as it is.
type WebhookEndpointUpdate struct {
	URL    *string  `json:"url,omitempty"`
	Events []string `json:"events,omitempty"`
	Status *string  `json:"status,omitempty"`
}

func (c *Client) UpdateWebhookEndpoint(ctx context.Context, id string, u WebhookEndpointUpdate) (*WebhookEndpoint, error) {
	return call[WebhookEndpoint](ctx, c, http.MethodPut, "/webhook-endpoints/"+url.PathEscape(id), u)
}

func (c *Client) DeleteWebhookEndpoint(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/webhook-endpoints/"+url.PathEscape(id), nil, nil)
}

// RotateWebhookSecret replaces the signing secret. The old one stops working at once.
func (c *Client) RotateWebhookSecret(ctx context.Context, id string) (*WebhookEndpoint, error) {
	return call[WebhookEndpoint](ctx, c, http.MethodPost, "/webhook-endpoints/"+url.PathEscape(id)+"/rotate-secret", nil)
}

// WebhookDelivery is one event on its way to one endpoint.
type WebhookDelivery struct {
	ID          int64      `json:"id"`
	Endpoint    string     `json:"endpoint"`
	Event       string     `json:"event"`
	Type        string     `json:"type"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	LastStatus  *int       `json:"last_status,omitempty"`
	LastError   *string    `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type ListDeliveriesParams struct {
	Endpoint      string
	Limit         int
	StartingAfter int64
}

func (c *Client) ListWebhookDeliveries(ctx context.Context, p ListDeliveriesParams) ([]WebhookDelivery, error) {
	values := url.Values{}
	if p.Endpoint != "" {
		values.Set("endpoint", p.Endpoint)
	}
	addInt(values, "limit", p.Limit)
	if p.StartingAfter > 0 {
		values.Set("starting_after", strconv.FormatInt(p.StartingAfter, 10))
	}
	page, err := call[struct {
		Data []WebhookDelivery `json:"data"`
	}](ctx, c, http.MethodGet, "/webhook-deliveries"+query(values), nil)
	if err != nil {
		return nil, err
	}
	return page.Data, nil
}

func (c *Client) RetryWebhookDelivery(ctx context.Context, id int64) error {
	return c.Do(ctx, http.MethodPost, "/webhook-deliveries/"+strconv.FormatInt(id, 10)+"/retry", nil, nil)
}

// Usage is what you used in a period.
type Usage struct {
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	Livemode    bool      `json:"livemode"`
	Customers   int       `json:"customers"`
	Enrolled    int       `json:"enrolled_customers"`
	Records     int       `json:"records"`
	Sessions    int       `json:"sessions"`
	Disclosures int       `json:"disclosures"`
}

// GetUsage counts usage. Zero times mean this month so far.
func (c *Client) GetUsage(ctx context.Context, from, to time.Time) (*Usage, error) {
	values := url.Values{}
	if !from.IsZero() {
		values.Set("from", from.UTC().Format(time.RFC3339))
	}
	if !to.IsZero() {
		values.Set("to", to.UTC().Format(time.RFC3339))
	}
	return call[Usage](ctx, c, http.MethodGet, "/usage"+query(values), nil)
}

// AuditEvent is one entry of the audit log.
type AuditEvent struct {
	ID         int64          `json:"id"`
	Type       string         `json:"type"`
	OccurredAt time.Time      `json:"occurred_at"`
	User       string         `json:"user,omitempty"`
	APIKey     string         `json:"api_key,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
}

func (c *Client) ListAuditEvents(ctx context.Context, limit int, startingAfter int64) ([]AuditEvent, error) {
	values := url.Values{}
	addInt(values, "limit", limit)
	if startingAfter > 0 {
		values.Set("starting_after", strconv.FormatInt(startingAfter, 10))
	}
	page, err := call[struct {
		Data []AuditEvent `json:"data"`
	}](ctx, c, http.MethodGet, "/audit-events"+query(values), nil)
	if err != nil {
		return nil, err
	}
	return page.Data, nil
}

// DisclosureKey is a public key you receive disclosures with. Fingerprint is not a secret: keep it in your app config and send it
// with every disclosure request.
type DisclosureKey struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Suite            string     `json:"suite"`
	PublicKey        string     `json:"public_key"`
	Fingerprint      string     `json:"fingerprint"`
	FingerprintShort string     `json:"fingerprint_short"`
	Status           string     `json:"status"`
	Livemode         bool       `json:"livemode"`
	RegisteredAt     time.Time  `json:"registered_at"`
	RetiresAt        *time.Time `json:"retires_at"`
	RetiredAt        *time.Time `json:"retired_at"`
}

// ListDisclosureKeys returns the keys of the key's mode, newest first.
func (c *Client) ListDisclosureKeys(ctx context.Context) ([]DisclosureKey, error) {
	list, err := call[struct {
		Data []DisclosureKey `json:"data"`
	}](ctx, c, http.MethodGet, "/disclosure-keys", nil)
	if err != nil {
		return nil, err
	}
	return list.Data, nil
}

// RegisterDisclosureKey registers a public key, given base64 encoded. It becomes active at once, and the key it replaces keeps
// working for the grace period. Send only the public key.
func (c *Client) RegisterDisclosureKey(ctx context.Context, name, suite, publicKey string, opts ...RequestOption) (*DisclosureKey, error) {
	return call[DisclosureKey](ctx, c, http.MethodPost, "/disclosure-keys", map[string]string{"name": name, "suite": suite, "public_key": publicKey}, opts...)
}

// RetireDisclosureKey stops a key at once and cancels the requests that wait for it.
func (c *Client) RetireDisclosureKey(ctx context.Context, id string) (*DisclosureKey, error) {
	return call[DisclosureKey](ctx, c, http.MethodPost, "/disclosure-keys/"+url.PathEscape(id)+"/retire", nil)
}

// CreateDisclosureParams asks for a disclosure. Fingerprint is the fingerprint of your disclosure key.
//
// Send Customer, Record, or both. With both, the record must belong to the customer. With only the customer, the customer's one
// record that holds every key is used; if none or more than one fits, the call fails and says so.
type CreateDisclosureParams struct {
	Customer    string   `json:"customer,omitempty"`
	Record      string   `json:"record,omitempty"`
	Keys        []string `json:"keys"`
	Reason      string   `json:"reason"`
	ExpiresIn   int      `json:"expires_in,omitempty"`
	Fingerprint string   `json:"disclosure_key_fingerprint"`
}

// Disclosure is a request to see named keys of one record. It holds names only, never values.
type Disclosure struct {
	ID        string     `json:"id"`
	Record    string     `json:"record"`
	Customer  string     `json:"customer"`
	Keys      []string   `json:"keys"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	Livemode  bool       `json:"livemode"`
	KeyID     string     `json:"disclosure_key"`
	ExpiresAt time.Time  `json:"expires_at"`
	DecidedAt *time.Time `json:"decided_at"`
	// AckedAt is when you acknowledged the envelope; the vault deleted it then. EnvelopeReady is true while you can still fetch it.
	AckedAt       *time.Time `json:"acked_at"`
	EnvelopeReady bool       `json:"envelope_ready"`
	CreatedAt     time.Time  `json:"created_at"`
}

type DisclosurePage struct {
	Data    []Disclosure `json:"data"`
	HasMore bool         `json:"has_more"`
}

// ListDisclosuresParams narrows and pages the list. Status is pending, approved, rejected, cancelled or expired.
type ListDisclosuresParams struct {
	Status        string
	Limit         int
	StartingAfter string
}

// CreateDisclosure asks one customer to let you see named keys. Then start a session with the approve purpose and this id.
func (c *Client) CreateDisclosure(ctx context.Context, p CreateDisclosureParams, opts ...RequestOption) (*Disclosure, error) {
	return call[Disclosure](ctx, c, http.MethodPost, "/disclosures", p, opts...)
}

func (c *Client) GetDisclosure(ctx context.Context, id string) (*Disclosure, error) {
	return call[Disclosure](ctx, c, http.MethodGet, "/disclosures/"+url.PathEscape(id), nil)
}

func (c *Client) ListDisclosures(ctx context.Context, p ListDisclosuresParams) (*DisclosurePage, error) {
	values := url.Values{}
	if p.Status != "" {
		values.Set("status", p.Status)
	}
	addInt(values, "limit", p.Limit)
	if p.StartingAfter != "" {
		values.Set("starting_after", p.StartingAfter)
	}
	return call[DisclosurePage](ctx, c, http.MethodGet, "/disclosures"+query(values), nil)
}

// CancelDisclosure stops a request that still waits for the customer.
func (c *Client) CancelDisclosure(ctx context.Context, id string) (*Disclosure, error) {
	return call[Disclosure](ctx, c, http.MethodPost, "/disclosures/"+url.PathEscape(id)+"/cancel", nil)
}

// GetDisclosureEnvelope fetches the sealed values of an approved request, as the JSON the vault sent. Open it with disclosure.OpenEnvelope,
// then call AckDisclosure. You have 15 minutes after the customer approves.
func (c *Client) GetDisclosureEnvelope(ctx context.Context, id string) (json.RawMessage, error) {
	raw, err := call[json.RawMessage](ctx, c, http.MethodGet, "/disclosures/"+url.PathEscape(id)+"/envelope", nil)
	if err != nil {
		return nil, err
	}
	return *raw, nil
}

// AckDisclosure tells the vault that you have the envelope and opened it. The vault deletes it. It is safe to call twice.
func (c *Client) AckDisclosure(ctx context.Context, id string) (*Disclosure, error) {
	return call[Disclosure](ctx, c, http.MethodPost, "/disclosures/"+url.PathEscape(id)+"/ack", nil)
}

// KeySummary is a key of a record: its name, label, type and version. You never see a value.
type KeySummary struct {
	Name      string    `json:"name"`
	Label     string    `json:"label,omitempty"`
	Type      string    `json:"type"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Record is what a customer keeps with you, as you see it: the token and the key names.
type Record struct {
	Token     string       `json:"token"`
	Customer  string       `json:"customer"`
	Version   int          `json:"version"`
	Keys      []KeySummary `json:"keys"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// RecordPage is one page of records, newest first.
type RecordPage struct {
	Data    []Record `json:"data"`
	HasMore bool     `json:"has_more"`
}

// ListRecordsParams narrows a list of one customer's records. StartingAfter is the token of the last record of the previous page.
type ListRecordsParams struct {
	Customer      string
	Limit         int
	StartingAfter string
}

// ListRecords lists a customer's records: tokens and key names, never values.
func (c *Client) ListRecords(ctx context.Context, p ListRecordsParams) (*RecordPage, error) {
	values := url.Values{}
	values.Set("customer", p.Customer)
	addInt(values, "limit", p.Limit)
	if p.StartingAfter != "" {
		values.Set("starting_after", p.StartingAfter)
	}
	return call[RecordPage](ctx, c, http.MethodGet, "/records"+query(values), nil)
}

// GetRecord returns one record: its token and key names.
func (c *Client) GetRecord(ctx context.Context, token string) (*Record, error) {
	return call[Record](ctx, c, http.MethodGet, "/records/"+url.PathEscape(token), nil)
}
