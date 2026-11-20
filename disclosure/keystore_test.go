package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
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

func TestAdvanceLastEventNeverGoesDown(t *testing.T) {
	s := &MemoryKeyStore{}
	for _, c := range []struct {
		created int64
		want    bool
		last    int64
	}{{10, true, 10}, {20, true, 20}, {15, false, 20}, {20, true, 20}, {0, false, 20}} {
		got, err := s.AdvanceLastEvent("cus_1", c.created)
		if err != nil || got != c.want {
			t.Errorf("AdvanceLastEvent(%d) = %v, %v; want %v", c.created, got, err, c.want)
		}
		if last, _ := s.LastEvent("cus_1"); last != c.last {
			t.Errorf("after %d the clock is %d, want %d", c.created, last, c.last)
		}
	}
}

func TestAdvanceLastEventAtOnceNeverLowersTheClock(t *testing.T) {
	s := &MemoryKeyStore{}
	const n = 64
	var wg sync.WaitGroup
	var refused atomic.Int32
	start := make(chan struct{})
	// One event is newer than all others. Events older than it are refused only if it came first, so every call must give the answer
	// that matches the clock at its own moment: a refused time is always below the clock, and the clock never goes down.
	for i := int64(1); i <= n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := s.AdvanceLastEvent("cus_1", i)
			if err != nil {
				t.Error(err)
			}
			if !ok {
				refused.Add(1)
				if last, _ := s.LastEvent("cus_1"); last <= i {
					t.Errorf("event %d was refused but the clock is %d", i, last)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if last, _ := s.LastEvent("cus_1"); last != n {
		t.Errorf("the clock is %d, want %d", last, n)
	}
}

func TestObserveEventAtOnceRefusesTheStaleEventExactlyOnce(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	for range 200 {
		s := &MemoryKeyStore{}
		if _, err := s.AdvanceLastEvent("cus_1", 20); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for i, e := range []*webhook.Event{event("customer.enrolled", "cus_1", a, 10), event("customer.enrolled", "cus_1", b, 30)} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = ObserveEvent(s, e, ObserveOptions{})
			}()
		}
		close(start)
		wg.Wait()
		if !errors.Is(errs[0], ErrStaleEvent) {
			t.Fatalf("the stale event got %v, want ErrStaleEvent", errs[0])
		}
		if errs[1] != nil {
			t.Fatalf("the newer event failed: %v", errs[1])
		}
		if last, _ := s.LastEvent("cus_1"); last != 30 {
			t.Fatalf("the clock is %d, want 30", last)
		}
		if held, _ := s.Get("cus_1"); !held.Equal(ed25519.PublicKey(b)) {
			t.Fatal("the stale event changed the key")
		}
	}
}

func TestAStaleEventDoesNotCallApproveReset(t *testing.T) {
	s := &MemoryKeyStore{}
	a := make([]byte, 32)
	if err := ObserveEvent(s, event("customer.enrolled", "cus_1", a, 20), ObserveOptions{}); err != nil {
		t.Fatal(err)
	}
	called := false
	opts := ObserveOptions{ApproveReset: func(string, string) (bool, error) { called = true; return true, nil }}
	if err := ObserveEvent(s, event("customer.reset", "cus_1", nil, 10), opts); !errors.Is(err, ErrStaleEvent) {
		t.Fatalf("got %v, want ErrStaleEvent", err)
	}
	if called {
		t.Error("ApproveReset ran for a stale event")
	}
	if _, err := s.Get("cus_1"); err != nil {
		t.Error("the key must stay")
	}
}

func TestMemoryKeyStoreGetReturnsCopy(t *testing.T) {
	store := &MemoryKeyStore{}
	key := ed25519.PublicKey(bytes.Repeat([]byte{7}, ed25519.PublicKeySize))
	if err := store.Put("cus_1", key); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get("cus_1")
	got[0] = 0
	again, _ := store.Get("cus_1")
	if !again.Equal(key) {
		t.Fatal("changing a returned key changed the kept key")
	}
}
