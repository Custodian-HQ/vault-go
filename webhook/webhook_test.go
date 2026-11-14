package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
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
	event.Type = "session.completed"
	if _, err := event.CustomerSignInLimitReached(); err == nil {
		t.Error("another event type must be refused")
	}
}

func sign(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func at(t *testing.T, ts int64) {
	t.Helper()
	old := now
	now = func() time.Time { return time.Unix(ts, 0) }
	t.Cleanup(func() { now = old })
}

func TestParseEventGivesTheEventOfAGoodRequest(t *testing.T) {
	const secret, ts = "whsec_test_secret", 1700000000
	body := []byte(`{"id":"evt_1","type":"session.completed","created":1700000000,"livemode":true,"data":{"object":{"id":"ses_1"}}}`)
	at(t, ts+30)
	event, err := ParseEvent(secret, sign(secret, ts, body), body, 0)
	if err != nil || event == nil {
		t.Fatalf("a good request: %v", err)
	}
	if event.ID != "evt_1" || event.Type != "session.completed" || event.Created != ts || !event.Livemode || string(event.Data.Object) != `{"id":"ses_1"}` {
		t.Errorf("the event was read wrong: %+v", event)
	}

	if _, err := ParseEvent("whsec_other", sign(secret, ts, body), body, 0); !errors.Is(err, ErrBadSignature) {
		t.Errorf("another secret: %v", err)
	}
	if _, err := ParseEvent(secret, sign(secret, ts, body), append(bytes.Clone(body), ' '), 0); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a body that changed after it was signed: %v", err)
	}
}

func TestParseEventRefusesABodyThatIsNotAnEventEvenWithAGoodSignature(t *testing.T) {
	const secret, ts = "whsec_test_secret", 1700000000
	at(t, ts)
	body := []byte(`{"id":"evt_1","type":`)
	event, err := ParseEvent(secret, sign(secret, ts, body), body, 0)
	if err == nil || event != nil {
		t.Fatalf("malformed JSON gave %+v, %v", event, err)
	}
	for _, sentinel := range []error{ErrBadHeader, ErrBadSignature, ErrStale} {
		if errors.Is(err, sentinel) {
			t.Errorf("a parse error must not look like %v", sentinel)
		}
	}
}

func TestTheToleranceIsTheOneYouGiveAndZeroMeansTheDefault(t *testing.T) {
	const secret, ts = "whsec_test_secret", 1700000000
	body := []byte(`{"id":"evt_1"}`)
	header := sign(secret, ts, body)
	for _, c := range []struct {
		name      string
		age       time.Duration
		tolerance time.Duration
		want      error
	}{
		{"inside the default", 4 * time.Minute, 0, nil},
		{"outside the default", 6 * time.Minute, 0, ErrStale},
		{"a looser tolerance takes it", 6 * time.Minute, 15 * time.Minute, nil},
		{"a stricter tolerance refuses it", 2 * time.Minute, time.Minute, ErrStale},
		{"a stricter tolerance in the future", -2 * time.Minute, time.Minute, ErrStale},
		{"exactly the tolerance", time.Minute, time.Minute, nil},
		{"a negative tolerance means the default", 4 * time.Minute, -time.Second, nil},
		{"a negative tolerance and an old request", 6 * time.Minute, -time.Second, ErrStale},
	} {
		got := Verify(secret, header, body, c.tolerance, time.Unix(ts, 0).Add(c.age))
		if !errors.Is(got, c.want) || (c.want == nil && got != nil) {
			t.Errorf("%s: want %v, got %v", c.name, c.want, got)
		}
		at(t, ts+int64(c.age/time.Second))
		_, err := ParseEvent(secret, header, body, c.tolerance)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s (ParseEvent): want %v, got %v", c.name, c.want, err)
		}
	}
}

func TestVerifyRefusesAnEmptySecret(t *testing.T) {
	body := []byte(`{"id":"evt_1"}`)
	mac := hmac.New(sha256.New, nil)
	mac.Write([]byte("1700000000."))
	mac.Write(body)
	header := "t=1700000000,v1=" + hex.EncodeToString(mac.Sum(nil))
	if err := Verify("", header, body, 0, time.Unix(1700000000, 0)); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("an empty secret must be refused, got %v", err)
	}
}
