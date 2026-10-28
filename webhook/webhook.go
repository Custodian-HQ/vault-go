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
)

// Verify checks the header against the raw request body, exactly as received. Pass the endpoint's secret (whsec_...).
// A zero tolerance means DefaultTolerance. The header may hold several v1 signatures (during a secret rotation): one
// match is enough.
func Verify(secret, header string, body []byte, tolerance time.Duration, now time.Time) error {
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
	if err := Verify(secret, header, body, tolerance, time.Now()); err != nil {
		return nil, err
	}
	var event Event
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

// EventRecoveryStatusChanged is the type of the event that says share recovery turned on or off for a customer.
const EventRecoveryStatusChanged = "customer.recovery_status_changed"

// RecoveryStatusChanged is the object of a customer.recovery_status_changed event. It carries metadata only. Status is "on" or "off".
// Reason is a code such as holder_removed, device_lost, holder_enrolled or secret_recovery; do not depend on the list being closed.
// Holders counts the holders with keys after the change.
type RecoveryStatusChanged struct {
	Customer  string `json:"customer"`
	Livemode  bool   `json:"livemode"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Holders   int    `json:"holders"`
	Threshold int    `json:"threshold"`
	ChangedAt string `json:"changed_at"`
}

// RecoveryStatusChanged reads the object of a customer.recovery_status_changed event. It fails for any other event type.
func (e *Event) RecoveryStatusChanged() (*RecoveryStatusChanged, error) {
	if e.Type != EventRecoveryStatusChanged {
		return nil, errors.New("webhook: not a " + EventRecoveryStatusChanged + " event")
	}
	var out RecoveryStatusChanged
	if err := json.Unmarshal(e.Data.Object, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EventRecoveryActionRequired is the type of the event that says the customer must unlock recovery settings so the shares are dealt again.
const EventRecoveryActionRequired = "recovery.action_required"

// RecoveryActionRequired is the object of a recovery.action_required event. It carries metadata only. HolderType is "contact" or "device".
// Reason is holder_added, holder_removed or device_lost; do not depend on the list being closed.
type RecoveryActionRequired struct {
	Customer    string `json:"customer"`
	Livemode    bool   `json:"livemode"`
	Holder      string `json:"holder"`
	HolderType  string `json:"holder_type"`
	Reason      string `json:"reason"`
	RequestedAt string `json:"requested_at"`
}

// RecoveryActionRequired reads the object of a recovery.action_required event. It fails for any other event type.
func (e *Event) RecoveryActionRequired() (*RecoveryActionRequired, error) {
	if e.Type != EventRecoveryActionRequired {
		return nil, errors.New("webhook: not a " + EventRecoveryActionRequired + " event")
	}
	var out RecoveryActionRequired
	if err := json.Unmarshal(e.Data.Object, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EventRecoveryHolderDeclined is the type of the event that says a trusted contact did not expect a release request and declined it.
const EventRecoveryHolderDeclined = "recovery.holder_declined"

// RecoveryHolderDeclined is the object of a recovery.holder_declined event. It carries metadata only: no name and no email of the contact.
// Other holders' requests stay open.
type RecoveryHolderDeclined struct {
	Customer   string `json:"customer"`
	Livemode   bool   `json:"livemode"`
	Holder     string `json:"holder"`
	HolderType string `json:"holder_type"`
	Recovery   string `json:"recovery"`
	DeclinedAt string `json:"declined_at"`
}

// RecoveryHolderDeclined reads the object of a recovery.holder_declined event. It fails for any other event type.
func (e *Event) RecoveryHolderDeclined() (*RecoveryHolderDeclined, error) {
	if e.Type != EventRecoveryHolderDeclined {
		return nil, errors.New("webhook: not a " + EventRecoveryHolderDeclined + " event")
	}
	var out RecoveryHolderDeclined
	if err := json.Unmarshal(e.Data.Object, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
