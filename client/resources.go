package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
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
	ID          string        `json:"id"`
	ExternalRef string        `json:"external_ref"`
	Livemode    bool          `json:"livemode"`
	State       CustomerState `json:"state"`
	Enrolled    bool          `json:"enrolled"`
	// VaultSignKey is the customer's public signing key, base64url. Keep the one you got in the customer.enrolled webhook and check envelopes
	// against that one; do not rely on this field alone.
	VaultSignKey string `json:"vault_sign_key,omitempty"`
	// FirstName and LastName are the name you offered, until the customer confirms or corrects it at enrolment (NameConfirmed). After that you
	// cannot change it.
	FirstName     string    `json:"first_name,omitempty"`
	LastName      string    `json:"last_name,omitempty"`
	NameConfirmed bool      `json:"name_confirmed"`
	CreatedAt     time.Time `json:"created_at"`
	// ResetAt is when the customer last confirmed a reset. It is nil if never. While State is "reset: enrolment needed", the customer must enrol again.
	ResetAt *time.Time `json:"reset_at,omitempty"`
}

// Who started a reset, as the customer.reset webhook says it.
const (
	InitiatedByBusiness        = "business"
	InitiatedByCustomerRequest = "customer_request"
)

// CustomerResetRequestedEvent is the object of the customer.reset_requested webhook. The customer asked for a reset; nothing was deleted.
// To start one, call ResetCustomer. At most 3 requests per customer per day are sent.
type CustomerResetRequestedEvent struct {
	ID          string    `json:"id"`
	ExternalRef string    `json:"external_ref"`
	Livemode    bool      `json:"livemode"`
	RequestedAt time.Time `json:"requested_at"`
}

// CustomerResetEvent is the object of the customer.reset webhook. InitiatedBy is InitiatedByCustomerRequest if a customer.reset_requested came
// before for this customer, and InitiatedByBusiness if not.
type CustomerResetEvent struct {
	ID          string    `json:"id"`
	ExternalRef string    `json:"external_ref"`
	Livemode    bool      `json:"livemode"`
	ResetAt     time.Time `json:"reset_at"`
	InitiatedBy string    `json:"initiated_by"`
}

// CustomerPage is one page of customers. HasMore is true when another page follows: ask again with StartingAfter set to the id of the last customer.
type CustomerPage struct {
	Data    []Customer `json:"data"`
	HasMore bool       `json:"has_more"`
}

// ListCustomersParams narrows and pages the list. StartingAfter is the id of the last customer of the previous page.
type ListCustomersParams struct {
	Limit         int
	StartingAfter string
	ExternalRef   string
	// State narrows the list to CustomerActive or CustomerResetEnrolmentNeeded (reset, and must enrol again).
	State CustomerState
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
	if p.State != "" {
		values.Set("state", string(p.State))
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
	Customer  string  `json:"customer"`
	Purpose   Purpose `json:"purpose"`
	ReturnURL string  `json:"return_url"`
	State     string  `json:"state"`
	Template  string  `json:"template,omitempty"`
	Keys      []Key   `json:"keys,omitempty"`
	// Record is the record token. A view needs it. An entry may name one to add keys to that record.
	Record     string `json:"record,omitempty"`
	Disclosure string `json:"disclosure,omitempty"`
}

// Session is one visit of a customer to the vault. URL is only set by CreateSession.
type Session struct {
	ID          string        `json:"id"`
	Customer    string        `json:"customer"`
	Purpose     Purpose       `json:"purpose"`
	Status      SessionStatus `json:"status"`
	Livemode    bool          `json:"livemode"`
	ReturnURL   string        `json:"return_url"`
	State       string        `json:"state"`
	ExpiresAt   time.Time     `json:"expires_at"`
	CreatedAt   time.Time     `json:"created_at"`
	CompletedAt *time.Time    `json:"completed_at,omitempty"`
	CancelledAt *time.Time    `json:"cancelled_at,omitempty"`
	// Record is the record this visit added to or shows. For an entry that makes a new record, it is set once the customer saved.
	Record string `json:"record,omitempty"`
	URL    string `json:"url,omitempty"`
	// SecretNotReplayable is true on a repeat of a call that made a session or a reset with the same idempotency key. The one-time URL is not in a
	// repeat: make a new session or reset with a new key.
	SecretNotReplayable bool     `json:"secret_not_replayable,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
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

// ReplaceTemplate replaces all keys of an existing template. Sessions already made keep the keys they were made with.
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

// SetRecoveryPolicy sets how many holders are needed to recover a customer's vault. The threshold must be between 2 and 10.
func (c *Client) SetRecoveryPolicy(ctx context.Context, threshold int) (*RecoveryPolicy, error) {
	return call[RecoveryPolicy](ctx, c, http.MethodPut, "/recovery-policy", RecoveryPolicy{RecoveryThreshold: threshold})
}

// ResetContactText is the text a customer reads after they ask you for a reset.
type ResetContactText struct {
	Text string `json:"text"`
}

// GetResetContactText returns that text: yours, or the default "Contact the business that gave you this link".
func (c *Client) GetResetContactText(ctx context.Context) (*ResetContactText, error) {
	return call[ResetContactText](ctx, c, http.MethodGet, "/reset-contact-text", nil)
}

// SetResetContactText sets it. It is plain text of 1 to 200 characters. The customer always has the button to ask; you cannot turn it off.
func (c *Client) SetResetContactText(ctx context.Context, text string) (*ResetContactText, error) {
	return call[ResetContactText](ctx, c, http.MethodPut, "/reset-contact-text", ResetContactText{Text: text})
}

// WebhookEndpoint is a receiver. A member makes, changes, deletes and rotates endpoints in the Console only. With an API key you can only list them.
type WebhookEndpoint struct {
	ID        string                `json:"id"`
	URL       string                `json:"url"`
	Events    []string              `json:"events"`
	Livemode  bool                  `json:"livemode"`
	Status    WebhookEndpointStatus `json:"status"`
	CreatedAt time.Time             `json:"created_at"`
	// SecretLast4 is the last 4 characters of the signing secret, to tell secrets apart.
	SecretLast4 string `json:"secret_last4,omitempty"`
	// FailingDeliveries counts events still retrying, plus events that gave up in the last 24 hours. LastDeliveryAt is when the newest event was
	// delivered, gave up, or was queued. Both are filled in lists only.
	FailingDeliveries int        `json:"failing_deliveries"`
	LastDeliveryAt    *time.Time `json:"last_delivery_at,omitempty"`
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

// WebhookDelivery is one event on its way to one endpoint.
type WebhookDelivery struct {
	ID          int64                 `json:"id"`
	Endpoint    string                `json:"endpoint"`
	Event       string                `json:"event"`
	Type        string                `json:"type"`
	Status      WebhookDeliveryStatus `json:"status"`
	Attempts    int                   `json:"attempts"`
	MaxAttempts int                   `json:"max_attempts"`
	// NextRetryAt is when the next try is due. It is set only while the delivery is pending or retrying.
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`
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

// RetryWebhookDelivery makes a waiting or failed delivery ready at once. A delivery that used all its tries gets one more.
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
	// NewCustomers7d counts customers made in the 7 days before the end of the period. PendingDisclosures counts requests that wait for a
	// customer now.
	NewCustomers7d     int `json:"new_customers_7d"`
	PendingDisclosures int `json:"pending_disclosures"`
}

// GetUsage counts usage. Zero times mean this month so far.
func (c *Client) GetUsage(ctx context.Context, from, to time.Time) (*Usage, error) {
	values := url.Values{}
	if !from.IsZero() {
		values.Set("from", from.UTC().Format(time.RFC3339Nano))
	}
	if !to.IsZero() {
		values.Set("to", to.UTC().Format(time.RFC3339Nano))
	}
	return call[Usage](ctx, c, http.MethodGet, "/usage"+query(values), nil)
}

// AuditEvent is one entry of the audit log.
type AuditEvent struct {
	ID         int64     `json:"id"`
	Type       string    `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`
	User       string    `json:"user,omitempty"`
	UserEmail  string    `json:"user_email,omitempty"`
	// Staff is true when Custodian staff caused the event. User and UserEmail are empty then.
	Staff       bool   `json:"staff,omitempty"`
	APIKeyLabel string `json:"api_key_label,omitempty"`
	// Livemode is nil for a change to the whole organization.
	Livemode *bool          `json:"livemode,omitempty"`
	APIKey   string         `json:"api_key,omitempty"`
	Payload  map[string]any `json:"payload,omitempty"`
}

// ListAuditEventsParams narrows and pages the audit log. A zero field is left out.
type ListAuditEventsParams struct {
	Limit int
	// StartingAfter is the id of the last event of the previous page.
	StartingAfter int64
	// Type is one event type, such as "api_key.created". Actor is "member" or "api_key".
	Type  string
	Actor string
	// From is included and To is not. Q matches a member's email, a key id, or text in the event (up to 100 characters).
	From, To time.Time
	Q        string
}

// ListAuditEvents lists the audit log, newest first. To read the next page, pass the id of the last event as StartingAfter.
func (c *Client) ListAuditEvents(ctx context.Context, p ListAuditEventsParams) ([]AuditEvent, error) {
	values := url.Values{}
	addInt(values, "limit", p.Limit)
	if p.StartingAfter > 0 {
		values.Set("starting_after", strconv.FormatInt(p.StartingAfter, 10))
	}
	if p.Type != "" {
		values.Set("type", p.Type)
	}
	if p.Actor != "" {
		values.Set("actor", p.Actor)
	}
	if !p.From.IsZero() {
		values.Set("from", p.From.UTC().Format(time.RFC3339Nano))
	}
	if !p.To.IsZero() {
		values.Set("to", p.To.UTC().Format(time.RFC3339Nano))
	}
	if p.Q != "" {
		values.Set("q", p.Q)
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
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	Suite            string              `json:"suite"`
	PublicKey        string              `json:"public_key"`
	Fingerprint      string              `json:"fingerprint"`
	FingerprintShort string              `json:"fingerprint_short"`
	Status           DisclosureKeyStatus `json:"status"`
	Livemode         bool                `json:"livemode"`
	RegisteredAt     time.Time           `json:"registered_at"`
	RetiresAt        *time.Time          `json:"retires_at"`
	RetiredAt        *time.Time          `json:"retired_at"`
}

// ListDisclosureKeys returns the keys of the key's mode, newest first. Keys are registered and retired in the Console, where a
// member confirms with a code. This API cannot change them.
func (c *Client) ListDisclosureKeys(ctx context.Context) ([]DisclosureKey, error) {
	list, err := call[struct {
		Data []DisclosureKey `json:"data"`
	}](ctx, c, http.MethodGet, "/disclosure-keys", nil)
	if err != nil {
		return nil, err
	}
	return list.Data, nil
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
	ID        string           `json:"id"`
	Record    string           `json:"record"`
	Customer  string           `json:"customer"`
	Keys      []string         `json:"keys"`
	Reason    string           `json:"reason"`
	Status    DisclosureStatus `json:"status"`
	Livemode  bool             `json:"livemode"`
	KeyID     string           `json:"disclosure_key"`
	ExpiresAt time.Time        `json:"expires_at"`
	DecidedAt *time.Time       `json:"decided_at"`
	// AckedAt is when you acknowledged the envelope; the vault deleted it then. EnvelopeReady is true while you can still fetch it.
	AckedAt       *time.Time `json:"acked_at"`
	EnvelopeReady bool       `json:"envelope_ready"`
	// Files are the file keys the customer approved, with the size of each stored file. It is empty unless EnvelopeReady is true.
	Files     []DisclosedFile `json:"files"`
	CreatedAt time.Time       `json:"created_at"`
}

// DisclosedFile is one approved file key. SizeBytes is the size of the stored, encrypted file.
type DisclosedFile struct {
	Key       string `json:"key"`
	SizeBytes int64  `json:"size_bytes"`
}

// DisclosurePage is one page of disclosure requests. HasMore is true when another page follows: ask again with StartingAfter set to the id of the last one.
type DisclosurePage struct {
	Data    []Disclosure `json:"data"`
	HasMore bool         `json:"has_more"`
}

// ListDisclosuresParams narrows and pages the list. Status is one of the DisclosureStatus values.
type ListDisclosuresParams struct {
	Status        DisclosureStatus
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
		values.Set("status", string(p.Status))
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
// download any files with DownloadDisclosedFile, then call AckDisclosure. You have 15 minutes after the customer approves.
func (c *Client) GetDisclosureEnvelope(ctx context.Context, id string) (json.RawMessage, error) {
	raw, err := call[json.RawMessage](ctx, c, http.MethodGet, "/disclosures/"+url.PathEscape(id)+"/envelope", nil)
	if err != nil {
		return nil, err
	}
	return *raw, nil
}

// ByteRange is one byte range of the encrypted file. Start counts from 0. Length is how many bytes to read; 0 means to the end of the file,
// so the zero value is the whole file.
type ByteRange struct {
	Start, Length int64
}

// DownloadFileParams changes a file download. With a Range the answer is that part only (206), for example to resume a download you
// save to disk. A part alone does not decrypt: join the parts, then open the whole file.
type DownloadFileParams struct {
	Range *ByteRange
}

// DownloadDisclosedFile returns the encrypted file that the customer approved under key (the file's key name), as the vault sends it. It
// does not load the file in memory: read the body, and close it. Decrypt it with Opened.OpenFile from the disclosure package, or save it
// first. The download works only while the envelope exists, so download before you call AckDisclosure.
//
// A file the customer replaced or removed after approving gives an error that matches ErrFileReplaced. A busy vault answers 429 busy: try
// again in a moment.
func (c *Client) DownloadDisclosedFile(ctx context.Context, id, key string, p DownloadFileParams) (io.ReadCloser, error) {
	path := "/disclosures/" + url.PathEscape(id) + "/files/" + url.PathEscape(key)
	if p.Range == nil {
		return c.stream(ctx, path, nil, http.StatusOK)
	}
	r := p.Range
	if r.Start < 0 || r.Length < 0 || r.Length > math.MaxInt64-r.Start {
		return nil, errors.New("custodian: a byte range must start at 0 or later and must not have a negative length")
	}
	value := "bytes=" + strconv.FormatInt(r.Start, 10) + "-"
	if r.Length > 0 {
		value += strconv.FormatInt(r.Start+r.Length-1, 10)
	}
	return c.stream(ctx, path, http.Header{"Range": {value}}, http.StatusPartialContent)
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
