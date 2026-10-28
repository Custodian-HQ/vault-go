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
// Any other type is ignored. The same event may arrive twice; that is harmless.
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
		held, err := store.Get(o.ID)
		switch {
		case errors.Is(err, ErrNoKey):
			return store.Put(o.ID, key)
		case err != nil:
			return err
		case !held.Equal(ed25519.PublicKey(key)):
			return ErrKeyChanged
		}
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
