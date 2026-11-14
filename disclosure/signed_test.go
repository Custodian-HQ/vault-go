package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sealed is an envelope made in test code, as the browser makes it, signed over the bytes it is given. tamper changes enc, commit or ct
// before the signature is made, so the signature is good for what the envelope holds and only the checks after it can refuse it.
func sealed(t *testing.T, tamper func(enc, commit, ct *[]byte)) ([]byte, Expected) {
	t.Helper()
	const suite = SuiteClassic
	private, public, err := GenerateKey(suite)
	if err != nil {
		t.Fatal(err)
	}
	signPublic, signPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := Expected{RequestID: "dsc_1", BusinessID: "org_1", CustomerID: "cus_1", KID: "dk_1", Keys: []string{"income"}, SignKey: signPublic, Suite: suite, PrivateKey: private}

	names := append([]string{}, want.Keys...)
	sort.Strings(names)
	rk := Fingerprint(suite, public)
	info := append(append(append([]byte(infoLabel), 0), want.BusinessID...), append(append([]byte{0}, want.RequestID...), append([]byte{0}, rk...)...)...)
	kem, _ := kemFor(suite)
	pub, err := kem.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(pub, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	plain := encodeMap([]pair{
		{text("request_id"), text(want.RequestID)}, {text("record"), text("rec_1")}, {text("approved_at"), uint_(1700000000)},
		{text("fields"), encodeMap([]pair{{text("income"), text("42")}})},
	})
	ct, err := sender.Seal(encodeTextArray(names), plain)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := sender.Export(commitLabel, commitSize)
	if err != nil {
		t.Fatal(err)
	}
	if tamper != nil {
		tamper(&enc, &commit, &ct)
	}

	statement := encodeMap([]pair{
		{text("v"), uint_(envelopeVersion)}, {text("suite"), text(suite)}, {text("request_id"), text(want.RequestID)}, {text("business_id"), text(want.BusinessID)},
		{text("customer_id"), text(want.CustomerID)}, {text("kid"), text(want.KID)}, {text("rk"), text(rk)}, {text("enc"), bstr(enc)}, {text("commit"), bstr(commit)}, {text("ct"), bstr(ct)},
	})
	sig := ed25519.Sign(signPrivate, append(append([]byte(signatureLabel), 0), statement...))
	b64 := base64.RawURLEncoding.EncodeToString
	raw, err := json.Marshal(wire{V: envelopeVersion, Suite: suite, RequestID: want.RequestID, BusinessID: want.BusinessID, CustomerID: want.CustomerID, KID: want.KID,
		Enc: b64(enc), Commit: b64(commit), CT: b64(ct), Sig: b64(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return raw, want
}

func TestAValidlySignedEnvelopeIsOpenedOnlyIfTheSealedPartsAreGood(t *testing.T) {
	raw, want := sealed(t, nil)
	got, err := OpenEnvelope(raw, want)
	if err != nil || got.Fields["income"] != "42" || got.Record != "rec_1" {
		t.Fatalf("the control envelope: %+v, %v", got, err)
	}

	flip := func(b *[]byte, i int) { *b = bytes.Clone(*b); (*b)[i] ^= 1 }
	for name, tamper := range map[string]func(enc, commit, ct *[]byte){
		"a changed ciphertext":     func(_, _, ct *[]byte) { flip(ct, 0) },
		"a changed ciphertext tag": func(_, _, ct *[]byte) { flip(ct, len(*ct)-1) },
		"a truncated ciphertext":   func(_, _, ct *[]byte) { *ct = (*ct)[:len(*ct)-1] },
		"a changed enc":            func(enc, _, _ *[]byte) { flip(enc, 0) },
		"a changed commitment":     func(_, commit, _ *[]byte) { flip(commit, 0) },
		"a short commitment":       func(_, commit, _ *[]byte) { *commit = (*commit)[:16] },
	} {
		raw, want := sealed(t, tamper)
		got, err := OpenEnvelope(raw, want)
		if !errors.Is(err, ErrPayload) || got != nil {
			t.Errorf("%s: the signature was good, but it must still be refused as ErrPayload: %+v, %v", name, got, err)
		}
	}

	raw, want = sealed(t, nil)
	want.Keys = []string{"income", "extra"}
	if _, err := OpenEnvelope(raw, want); !errors.Is(err, ErrPayload) {
		t.Errorf("another list of names: %v", err)
	}
}

func nested(maps int) []byte {
	out := bytes.Repeat([]byte{0xa1, 0x61, 0x61}, maps)
	return append(out, 0x01)
}

func TestTheCBORReaderStopsAtTheDepthLimit(t *testing.T) {
	if _, err := decode(nested(8)); err != nil {
		t.Errorf("8 nested maps are inside the limit: %v", err)
	}
	if _, err := decode(nested(9)); err == nil {
		t.Error("9 nested maps must be refused")
	}
	if _, err := decode(nested(10000)); err == nil {
		t.Error("a very deep item must be refused, not run out of stack")
	}
}

type onlyKeyStore struct{ KeyStore }

// gatedStore holds back a Get that found no key until a second caller found none too, so the two callers of Observe cannot avoid
// meeting between their check and their write. A Get that finds a key is not held, so a store that is checked and written in one step
// never waits.
type gatedStore struct {
	*MemoryKeyStore
	arrived atomic.Int32
	release chan struct{}
}

func (g *gatedStore) Get(id string) (ed25519.PublicKey, error) {
	key, err := g.MemoryKeyStore.Get(id)
	if errors.Is(err, ErrNoKey) {
		if g.arrived.Add(1) == 2 {
			close(g.release)
		}
		select {
		case <-g.release:
		case <-time.After(200 * time.Millisecond):
		}
	}
	return key, err
}

func TestTwoEnrolmentsAtOnceForOneCustomerPinOneKey(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	for round := 0; round < 50; round++ {
		store := &gatedStore{MemoryKeyStore: &MemoryKeyStore{}, release: make(chan struct{})}
		if _, ok := KeyStore(store).(AtomicKeyStore); !ok {
			t.Fatal("the test store must be atomic")
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, 2)
		for i, key := range [][]byte{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i] = Observe(store, "customer.enrolled", enrolled("cus_1", key))
			}()
		}
		close(start)
		wg.Wait()

		wins := 0
		for _, err := range results {
			switch {
			case err == nil:
				wins++
			case !errors.Is(err, ErrKeyChanged):
				t.Fatalf("round %d: %v", round, err)
			}
		}
		held, _ := store.MemoryKeyStore.Get("cus_1")
		winner := a
		if results[1] == nil {
			winner = b
		}
		if wins != 1 || !bytes.Equal(held, winner) {
			t.Fatalf("round %d: %d wins, results %v, key kept %x", round, wins, results, held)
		}
	}
}

func TestAStoreWithoutPutIfAbsentStillWorks(t *testing.T) {
	store := onlyKeyStore{&MemoryKeyStore{}}
	if _, ok := KeyStore(store).(AtomicKeyStore); ok {
		t.Fatal("the test store must not be atomic")
	}
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	if err := Observe(store, "customer.enrolled", enrolled("cus_1", a)); err != nil {
		t.Fatal(err)
	}
	if err := Observe(store, "customer.enrolled", enrolled("cus_1", a)); err != nil {
		t.Errorf("the same key twice: %v", err)
	}
	if err := Observe(store, "customer.enrolled", enrolled("cus_1", b)); !errors.Is(err, ErrKeyChanged) {
		t.Errorf("another key: %v", err)
	}
}

func TestPutIfAbsentKeepsTheFirstKey(t *testing.T) {
	store := &MemoryKeyStore{}
	a, b := ed25519.PublicKey(bytes.Repeat([]byte{1}, 32)), ed25519.PublicKey(bytes.Repeat([]byte{2}, 32))
	if stored, err := store.PutIfAbsent("cus_1", a); !stored || err != nil {
		t.Fatalf("first: %v %v", stored, err)
	}
	if stored, err := store.PutIfAbsent("cus_1", b); stored || err != nil {
		t.Fatalf("second: %v %v", stored, err)
	}
	if held, _ := store.Get("cus_1"); !held.Equal(a) {
		t.Error("the first key must stay")
	}
	a[0] = 9
	if held, _ := store.Get("cus_1"); held[0] == 9 {
		t.Error("the store must keep its own copy of the key")
	}
}
