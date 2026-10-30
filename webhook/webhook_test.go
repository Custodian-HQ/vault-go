package webhook

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// The cases are the shared known answers in the fixtures. The first signature in them was made by the API's own code.
func TestVerifyAgainstTheSharedKnownAnswers(t *testing.T) {
	raw, err := os.ReadFile("../testdata/fixtures/v1/webhook-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		HeaderName       string `json:"header_name"`
		ToleranceSeconds int    `json:"tolerance_seconds"`
		Secret           string
		Body             string
		Cases            []struct {
			Name   string
			Header string
			Now    int64
			Valid  bool
			Error  string
			Body   *string
		}
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.HeaderName != HeaderName || time.Duration(vector.ToleranceSeconds)*time.Second != DefaultTolerance {
		t.Fatalf("the header name or tolerance changed: %+v", vector)
	}
	wantErr := map[string]error{"stale": ErrStale, "signature": ErrBadSignature, "header": ErrBadHeader}
	for _, c := range vector.Cases {
		body := vector.Body
		if c.Body != nil {
			body = *c.Body
		}
		err := Verify(vector.Secret, c.Header, []byte(body), 0, time.Unix(c.Now, 0))
		switch {
		case c.Valid && err != nil:
			t.Errorf("%s: must be valid, got %v", c.Name, err)
		case !c.Valid && !errors.Is(err, wantErr[c.Error]):
			t.Errorf("%s: want %v, got %v", c.Name, wantErr[c.Error], err)
		}
	}
}

func TestParseEventReadsTheEventOnlyAfterTheSignatureChecks(t *testing.T) {
	body := []byte(`{"id":"evt_1","type":"session.completed","created":1700000000,"livemode":false,"data":{"object":{"id":"ses_1"}}}`)
	if _, err := ParseEvent("whsec_test_secret", "t=1,v1=00", body, 0); err == nil {
		t.Error("a wrong signature must not give an event")
	}
}

func TestRecoveryStatusChangedReadsItsObjectAndRefusesOtherEvents(t *testing.T) {
	var event Event
	body := `{"id":"evt_1","type":"customer.recovery_status_changed","created":1700000000,"livemode":true,"data":{"object":{"customer":"cus_1","livemode":true,"status":"off","reason":"device_lost","holders":2,"threshold":2,"changed_at":"2026-10-27T18:24:57Z"}}}`
	if err := json.Unmarshal([]byte(body), &event); err != nil {
		t.Fatal(err)
	}
	got, err := event.RecoveryStatusChanged()
	if err != nil || got.Status != "off" || got.Reason != "device_lost" || got.Holders != 2 || got.Threshold != 2 || got.Customer != "cus_1" {
		t.Fatalf("got %+v, %v", got, err)
	}
	event.Type = "session.completed"
	if _, err := event.RecoveryStatusChanged(); err == nil {
		t.Error("another event type must be refused")
	}
}

func TestRecoveryActionRequiredReadsItsObjectAndRefusesOtherEvents(t *testing.T) {
	var event Event
	body := `{"id":"evt_2","type":"recovery.action_required","created":1700000000,"livemode":true,"data":{"object":{"customer":"cus_1","livemode":true,"holder":"h_1","holder_type":"contact","reason":"holder_added","requested_at":"2026-10-27T18:24:57Z"}}}`
	if err := json.Unmarshal([]byte(body), &event); err != nil {
		t.Fatal(err)
	}
	got, err := event.RecoveryActionRequired()
	if err != nil || got.Holder != "h_1" || got.HolderType != "contact" || got.Reason != "holder_added" || got.Customer != "cus_1" {
		t.Fatalf("got %+v, %v", got, err)
	}
	event.Type = "customer.recovery_status_changed"
	if _, err := event.RecoveryActionRequired(); err == nil {
		t.Error("another event type must be refused")
	}
}

func TestRecoveryHolderDeclinedReadsItsObjectAndRefusesOtherEvents(t *testing.T) {
	var event Event
	body := `{"id":"evt_3","type":"recovery.holder_declined","created":1700000000,"livemode":true,"data":{"object":{"customer":"cus_1","livemode":true,"holder":"h_1","holder_type":"contact","recovery":"r_1","declined_at":"2026-10-27T18:24:57Z"}}}`
	if err := json.Unmarshal([]byte(body), &event); err != nil {
		t.Fatal(err)
	}
	got, err := event.RecoveryHolderDeclined()
	if err != nil || got.Holder != "h_1" || got.Recovery != "r_1" || got.Customer != "cus_1" || got.DeclinedAt == "" {
		t.Fatalf("got %+v, %v", got, err)
	}
	event.Type = "recovery.action_required"
	if _, err := event.RecoveryHolderDeclined(); err == nil {
		t.Error("another event type must be refused")
	}
}

func TestCustomerSignInLimitReachedReadsItsObjectAndRefusesOtherEvents(t *testing.T) {
	var event Event
	body := `{"id":"evt_4","type":"customer.sign_in_limit_reached","created":1700000000,"livemode":true,"data":{"object":{"customer":"cus_1","livemode":true,"brake":"keyring_read","limit":10,"reached_at":"2026-10-29T10:00:00Z"}}}`
	if err := json.Unmarshal([]byte(body), &event); err != nil {
		t.Fatal(err)
	}
	got, err := event.CustomerSignInLimitReached()
	if err != nil || got.Customer != "cus_1" || got.Brake != "keyring_read" || got.Limit != 10 || got.ReachedAt == "" {
		t.Fatalf("got %+v, %v", got, err)
	}
	event.Type = "recovery.action_required"
	if _, err := event.CustomerSignInLimitReached(); err == nil {
		t.Error("another event type must be refused")
	}
}
