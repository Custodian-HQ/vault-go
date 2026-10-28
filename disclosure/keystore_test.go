package disclosure

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
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
