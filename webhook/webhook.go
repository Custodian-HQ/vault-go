// Package webhook checks the webhooks Custodian sends to your server, and reads their events.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// HeaderName is the request header that carries the signature.
const HeaderName = "Custodian-Signature"

// DefaultTolerance is how far the signature's time may be from your clock.
const DefaultTolerance = 5 * time.Minute

var (
	ErrBadHeader    = errors.New("webhook: the signature header is malformed")
	ErrBadSignature = errors.New("webhook: the signature does not match")
	ErrStale        = errors.New("webhook: the timestamp is outside the tolerance")
	ErrNoSecret     = errors.New("webhook: the secret is empty")
)

// now is the clock of ParseEvent. A test replaces it.
var now = time.Now

// Verify checks the header against the raw request body, exactly as received. Pass the endpoint's secret (whsec_...).
// A zero tolerance means DefaultTolerance. The header may hold several v1 signatures: one match is enough. The API signs with one
// secret only, so after you rotate a secret, events fail until you deploy the new one.
func Verify(secret, header string, body []byte, tolerance time.Duration, now time.Time) error {
	// An empty key would let anyone sign a forged event.
	if secret == "" {
		return ErrNoSecret
	}
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	var timestamp int64
	var haveTimestamp bool
	var signatures [][]byte
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return ErrBadHeader
		}
		switch key {
		case "t":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return ErrBadHeader
			}
			timestamp, haveTimestamp = n, true
		case "v1":
			sig, err := hex.DecodeString(value)
			if err != nil {
				return ErrBadHeader
			}
			signatures = append(signatures, sig)
		}
	}
	if !haveTimestamp || len(signatures) == 0 {
		return ErrBadHeader
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	matched := false
	for _, sig := range signatures {
		if hmac.Equal(sig, want) { // no early exit, so timing does not show which one matched
			matched = true
		}
	}
	if !matched {
		return ErrBadSignature
	}
	if age := now.Sub(time.Unix(timestamp, 0)); age > tolerance || age < -tolerance {
		return ErrStale
	}
	return nil
}

// Event is the body of every webhook request. It carries metadata only.
type Event struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Created  int64  `json:"created"`
	Livemode bool   `json:"livemode"`
	Data     struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

// ParseEvent verifies the request and then reads its event. Use it as the first thing your handler does, with the raw
// body, before any other parsing. The same event can arrive more than once: ignore an id you have already handled.
func ParseEvent(secret, header string, body []byte, tolerance time.Duration) (*Event, error) {
	if err := Verify(secret, header, body, tolerance, now()); err != nil {
		return nil, err
	}
	var event Event
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

// EventCustomerSignInLimitReached is the type of the event that says a customer used the last slot of an hourly sign-in limit.
const EventCustomerSignInLimitReached = "customer.sign_in_limit_reached"

// CustomerSignInLimitReached is the object of a customer.sign_in_limit_reached event. It carries metadata only. Brake is sign_in_finish,
// keyring_read or failed_assertion; Limit is the hourly count.
type CustomerSignInLimitReached struct {
	Customer  string `json:"customer"`
	Livemode  bool   `json:"livemode"`
	Brake     string `json:"brake"`
	Limit     int    `json:"limit"`
	ReachedAt string `json:"reached_at"`
}

// CustomerSignInLimitReached reads the object of a customer.sign_in_limit_reached event. It fails for any other event type.
func (e *Event) CustomerSignInLimitReached() (*CustomerSignInLimitReached, error) {
	if e.Type != EventCustomerSignInLimitReached {
		return nil, errors.New("webhook: not a " + EventCustomerSignInLimitReached + " event")
	}
	var out CustomerSignInLimitReached
	if err := json.Unmarshal(e.Data.Object, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
