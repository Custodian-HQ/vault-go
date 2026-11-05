package disclosure

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
)

var (
	// ErrNoKey means you hold no signing key for the customer. You get the key from the customer.enrolled webhook. OpenEnvelopeFor does not
	// ask Custodian for it, because the key you check against must not come from the party you are checking.
	ErrNoKey = errors.New("disclosure: no signing key is kept for this customer")
	// ErrKeyChanged means a customer.enrolled event names another key than the one you kept. A customer's key changes only after a reset or
	// a deletion, and you hear of both with a webhook. Without one, treat this as an attack.
	ErrKeyChanged = errors.New("disclosure: the customer's signing key changed without a reset")
)

// KeyStore keeps each customer's vault-sign public key, as the customer.enrolled webhook gave it. Back it with your own database.
type KeyStore interface {
	Get(customerID string) (ed25519.PublicKey, error)
	Put(customerID string, key ed25519.PublicKey) error
	Delete(customerID string) error
}

// AtomicKeyStore is a KeyStore that can also keep a key only if none is kept, in one step. Observe uses it when the store has it, so two
// webhook events handled at the same time cannot both pin a key for one customer. A store on a database does this with one insert that does
// nothing on a conflict.
type AtomicKeyStore interface {
	KeyStore
	// PutIfAbsent keeps the key and returns true if the store held none for the customer. If it held one, it changes nothing and returns false.
	PutIfAbsent(customerID string, key ed25519.PublicKey) (stored bool, err error)
}

// MemoryKeyStore is a KeyStore in memory. It is for tests and for programs that do not restart.
type MemoryKeyStore struct {
	mu   sync.Mutex
	keys map[string]ed25519.PublicKey
}

func (m *MemoryKeyStore) Get(customerID string) (ed25519.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.keys[customerID]
	if !ok {
		return nil, ErrNoKey
	}
	return key, nil
}

func (m *MemoryKeyStore) Put(customerID string, key ed25519.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys == nil {
		m.keys = map[string]ed25519.PublicKey{}
	}
	m.keys[customerID] = append(ed25519.PublicKey(nil), key...)
	return nil
}

// PutIfAbsent is the AtomicKeyStore method.
func (m *MemoryKeyStore) PutIfAbsent(customerID string, key ed25519.PublicKey) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[customerID]; ok {
		return false, nil
	}
	if m.keys == nil {
		m.keys = map[string]ed25519.PublicKey{}
	}
	m.keys[customerID] = append(ed25519.PublicKey(nil), key...)
	return true, nil
}

func (m *MemoryKeyStore) Delete(customerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, customerID)
	return nil
}

// Observe keeps the signing key that a verified webhook event names. Call it for every event, after webhook.ParseEvent. It acts on three types:
//
//	customer.enrolled: keeps the key. If you already hold another key for the customer it returns ErrKeyChanged and keeps the old one.
//	customer.reset, customer.deleted: forgets the key, so the next enrolment can set a new one.
//
// Any other type is ignored. The same event may arrive twice; that is harmless. If your store is an AtomicKeyStore, two events handled at
// the same time for one customer cannot both keep a key. Events for one customer can still arrive in another order than they were sent: keep
// the id of each handled event, as the webhook guide says.
func Observe(store KeyStore, eventType string, object json.RawMessage) error {
	switch eventType {
	case "customer.enrolled":
		var o struct {
			ID           string `json:"id"`
			VaultSignKey string `json:"vault_sign_key"`
		}
		if err := json.Unmarshal(object, &o); err != nil || o.ID == "" {
			return ErrFormat
		}
		key, err := base64.RawURLEncoding.Strict().DecodeString(o.VaultSignKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return ErrFormat
		}
		return pin(store, o.ID, key)
	case "customer.reset", "customer.deleted":
		var o struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(object, &o); err != nil || o.ID == "" {
			return ErrFormat
		}
		return store.Delete(o.ID)
	}
	return nil
}

// pin keeps the key for a customer who has none, and refuses another key for one who has.
func pin(store KeyStore, id string, key ed25519.PublicKey) error {
	atomic, isAtomic := store.(AtomicKeyStore)
	for range 3 {
		if isAtomic {
			if stored, err := atomic.PutIfAbsent(id, key); err != nil || stored {
				return err
			}
		}
		held, err := store.Get(id)
		switch {
		case errors.Is(err, ErrNoKey) && !isAtomic:
			return store.Put(id, key)
		case errors.Is(err, ErrNoKey):
			continue // a reset or a deletion came between the two calls
		case err != nil:
			return err
		case !held.Equal(key):
			return ErrKeyChanged
		}
		return nil
	}
	return errors.New("disclosure: the key store answered PutIfAbsent and Get in ways that do not fit")
}

// OpenEnvelopeFor is OpenEnvelope with the customer's signing key taken from your store. It ignores want.SignKey. If the store holds no key
// for want.CustomerID it returns ErrNoKey and opens nothing.
func OpenEnvelopeFor(store KeyStore, raw []byte, want Expected) (*Opened, error) {
	key, err := store.Get(want.CustomerID)
	if err != nil {
		return nil, err
	}
	want.SignKey = key
	return OpenEnvelope(raw, want)
}
