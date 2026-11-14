package disclosure

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Custodian-HQ/vault-go/webhook"
)

func enrolled(customer string, key []byte) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"id": customer, "livemode": true, "vault_sign_key": base64.RawURLEncoding.EncodeToString(key), "mk_epoch": 1})
	return raw
}

func TestAnEnvelopeOpensWithTheKeyTheWebhookGave(t *testing.T) {
	for _, c := range loadFixture(t) {
		store := &MemoryKeyStore{}
		want := c.expected()
		want.SignKey = nil
		if _, err := OpenEnvelopeFor(store, c.Envelope, want); !errors.Is(err, ErrNoKey) {
			t.Fatalf("%s: with no key kept it must refuse: %v", c.Name, err)
		}
		key, _ := hex.DecodeString(c.SignKey)
		if err := Observe(store, "customer.enrolled", enrolled(c.CustomerID, key)); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenEnvelopeFor(store, c.Envelope, want); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
}

func TestAnotherKeyForAKnownCustomerIsRefusedUntilAResetOrADeletion(t *testing.T) {
	store := &MemoryKeyStore{}
	a, b := make([]byte, 32), make([]byte, 32)
	b[0] = 1
	if err := Observe(store, "customer.enrolled", enrolled("cus_1", a)); err != nil {
		t.Fatal(err)
	}
	if err := Observe(store, "customer.enrolled", enrolled("cus_1", a)); err != nil {
		t.Errorf("the same event twice is harmless: %v", err)
	}
	if err := Observe(store, "customer.enrolled", enrolled("cus_1", b)); !errors.Is(err, ErrKeyChanged) {
		t.Fatalf("another key must be refused: %v", err)
	}
	if held, _ := store.Get("cus_1"); !held.Equal(ed25519.PublicKey(a)) {
		t.Error("the first key must be kept")
	}
	// A request for a reset deletes nothing, so the pinned key stays.
	kept := &MemoryKeyStore{}
	_ = Observe(kept, "customer.enrolled", enrolled("cus_1", a))
	if err := Observe(kept, "customer.reset_requested", json.RawMessage(`{"id":"cus_1"}`)); err != nil {
		t.Fatal(err)
	}
	if err := Observe(kept, "customer.enrolled", enrolled("cus_1", b)); !errors.Is(err, ErrKeyChanged) {
		t.Errorf("after a reset request the old key must still be pinned: %v", err)
	}
	for _, kind := range []string{"customer.reset", "customer.deleted"} {
		s := &MemoryKeyStore{}
		_ = Observe(s, "customer.enrolled", enrolled("cus_1", a))
		if err := Observe(s, kind, json.RawMessage(`{"id":"cus_1"}`)); err != nil {
			t.Fatal(err)
		}
		if err := Observe(s, "customer.enrolled", enrolled("cus_1", b)); err != nil {
			t.Errorf("after %s a new key is accepted: %v", kind, err)
		}
	}
}

func TestObserveRefusesABadEventAndIgnoresOtherTypes(t *testing.T) {
	store := &MemoryKeyStore{}
	for name, object := range map[string]json.RawMessage{
		"no id":            json.RawMessage(`{"vault_sign_key":"AAAA"}`),
		"a short key":      enrolled("cus_1", make([]byte, 31)),
		"a key not base64": json.RawMessage(`{"id":"cus_1","vault_sign_key":"!!"}`),
		"not an object":    json.RawMessage(`[]`),
	} {
		if err := Observe(store, "customer.enrolled", object); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := Observe(store, "record.created", json.RawMessage(`{}`)); err != nil {
		t.Errorf("other types are ignored: %v", err)
	}
	if _, err := store.Get("cus_1"); !errors.Is(err, ErrNoKey) {
		t.Error("nothing must have been kept")
	}
}

func TestAnEnvelopeSignedByAnotherKeyIsRefusedEvenThoughTheStoreHasAKey(t *testing.T) {
	c := loadFixture(t)[0]
	store := &MemoryKeyStore{}
	other := make([]byte, 32)
	_ = Observe(store, "customer.enrolled", enrolled(c.CustomerID, other))
	if _, err := OpenEnvelopeFor(store, c.Envelope, c.expected()); !errors.Is(err, ErrSignature) {
		t.Errorf("want ErrSignature, got %v", err)
	}
}

func event(kind, customer string, key []byte, created int64) *webhook.Event {
	e := &webhook.Event{ID: "evt_x", Type: kind, Created: created}
	if kind == "customer.enrolled" {
		e.Data.Object = enrolled(customer, key)
	} else {
		e.Data.Object = json.RawMessage(`{"id":"` + customer + `"}`)
	}
	return e
}

func yes(string, string) (bool, error) { return true, nil }

func TestAResetNeedsTheBusinessToApproveIt(t *testing.T) {
	a, b := make([]byte, 32), make([]byte, 32)
	b[0] = 1
	for _, kind := range []string{"customer.reset", "customer.deleted"} {
		for name, opts := range map[string]ObserveOptions{
			"no callback":    {},
			"callback no":    {ApproveReset: func(string, string) (bool, error) { return false, nil }},
			"callback error": {ApproveReset: func(string, string) (bool, error) { return false, errors.New("lookup failed") }},
		} {
			s := &MemoryKeyStore{}
			_ = ObserveEvent(s, event("customer.enrolled", "cus_1", a, 1), opts)
			err := ObserveEvent(s, event(kind, "cus_1", nil, 2), opts)
			if err == nil || (name != "callback error" && !errors.Is(err, ErrResetNotApproved)) {
				t.Errorf("%s %s: %v", kind, name, err)
			}
			if held, _ := s.Get("cus_1"); !held.Equal(ed25519.PublicKey(a)) {
				t.Errorf("%s %s: the key must stay", kind, name)
			}
			if err := ObserveEvent(s, event("customer.enrolled", "cus_1", b, 3), opts); !errors.Is(err, ErrKeyChanged) {
				t.Errorf("%s %s: another key without an approved reset: %v", kind, name, err)
			}
		}
		s := &MemoryKeyStore{}
		opts := ObserveOptions{ApproveReset: yes}
		_ = ObserveEvent(s, event("customer.enrolled", "cus_1", a, 1), opts)
		if err := ObserveEvent(s, event(kind, "cus_1", nil, 2), opts); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get("cus_1"); !errors.Is(err, ErrNoKey) {
			t.Errorf("%s: an approved reset must forget the key", kind)
		}
		if err := ObserveEvent(s, event("customer.enrolled", "cus_1", b, 3), opts); err != nil {
			t.Errorf("%s: the new key after an approved reset: %v", kind, err)
		}
		if held, _ := s.Get("cus_1"); !held.Equal(ed25519.PublicKey(b)) {
			t.Errorf("%s: the new key must be kept", kind)
		}
	}
}

func TestAnOldRetriedEventCannotChangeThePin(t *testing.T) {
	a, b := make([]byte, 32), make([]byte, 32)
	b[0] = 1
	opts := ObserveOptions{ApproveReset: yes}

	// An old customer.enrolled(K1) that arrives after a newer reset is not pinned.
	s := &MemoryKeyStore{}
	_ = ObserveEvent(s, event("customer.enrolled", "cus_1", a, 10), opts)
	_ = ObserveEvent(s, event("customer.reset", "cus_1", nil, 20), opts)
	if err := ObserveEvent(s, event("customer.enrolled", "cus_1", a, 10), opts); !errors.Is(err, ErrStaleEvent) {
		t.Fatalf("an old enrolled event: %v", err)
	}
	if _, err := s.Get("cus_1"); !errors.Is(err, ErrNoKey) {
		t.Error("the old key must not be pinned again")
	}
	if err := ObserveEvent(s, event("customer.enrolled", "cus_1", b, 30), opts); err != nil {
		t.Fatal(err)
	}

	// An old customer.reset that arrives after a newer enrolled keeps the pin.
	if err := ObserveEvent(s, event("customer.reset", "cus_1", nil, 20), opts); !errors.Is(err, ErrStaleEvent) {
		t.Fatalf("an old reset event: %v", err)
	}
	if held, _ := s.Get("cus_1"); !held.Equal(ed25519.PublicKey(b)) {
		t.Error("the pin must stay")
	}

	// Events of the same second are all handled.
	if err := ObserveEvent(s, event("customer.reset", "cus_1", nil, 30), opts); err != nil {
		t.Errorf("a reset in the same second: %v", err)
	}
	if err := ObserveEvent(s, event("customer.enrolled", "cus_1", a, 30), opts); err != nil {
		t.Errorf("an enrolled event in the same second: %v", err)
	}

	// A stale event of another customer is not stale for this one, and a stale event does not move the clock.
	if err := ObserveEvent(s, event("customer.enrolled", "cus_2", a, 5), opts); err != nil {
		t.Errorf("another customer: %v", err)
	}
	if last, _ := s.LastEvent("cus_1"); last != 30 {
		t.Errorf("the clock moved to %d", last)
	}
}

func TestObserveEventWithAStoreThatHasNoClockSkipsTheOrderCheck(t *testing.T) {
	s := &plainStore{&MemoryKeyStore{}}
	a := make([]byte, 32)
	if err := ObserveEvent(s, event("customer.enrolled", "cus_1", a, 20), ObserveOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := ObserveEvent(s, event("customer.enrolled", "cus_1", a, 10), ObserveOptions{}); err != nil {
		t.Errorf("no clock, no order check: %v", err)
	}
}

type plainStore struct{ m *MemoryKeyStore }

func (p *plainStore) Get(id string) (ed25519.PublicKey, error) { return p.m.Get(id) }
func (p *plainStore) Put(id string, k ed25519.PublicKey) error { return p.m.Put(id, k) }
func (p *plainStore) Delete(id string) error                   { return p.m.Delete(id) }
