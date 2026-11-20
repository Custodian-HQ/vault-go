package disclosure

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"

	"github.com/Custodian-HQ/vault-go/webhook"
)

// The webhook event types that Observe acts on.
const (
	eventCustomerEnrolled = "customer.enrolled"
	eventCustomerReset    = "customer.reset"
	eventCustomerDeleted  = "customer.deleted"
)

var (
	// ErrNoKey means you hold no signing key for the customer. You get the key from the customer.enrolled webhook. OpenEnvelopeFor does not
	// ask Custodian for it, because the key you check against must not come from the party you are checking.
	ErrNoKey = errors.New("disclosure: no signing key is kept for this customer")
	// ErrKeyChanged means a customer.enrolled event names another key than the one you kept. A customer's key changes only after a reset or
	// a deletion, and you hear of both with a webhook. Without one, treat this as an attack.
	ErrKeyChanged = errors.New("disclosure: the customer's signing key changed without a reset")
	// ErrResetNotApproved means a customer.reset or customer.deleted event did not erase the kept key, because ObserveOptions.ApproveReset is not set
	// or said no. The key stays.
	ErrResetNotApproved = errors.New("disclosure: the reset was not approved, so the signing key stays. Set ObserveOptions.ApproveReset to approve resets")
	// ErrStaleEvent means the event is older than one already handled for the customer. Nothing changed. Treat it as handled and acknowledge the webhook.
	ErrStaleEvent = errors.New("disclosure: the event is older than one already handled for this customer")
)

// KeyStore keeps each customer's vault-sign public key, as the customer.enrolled webhook gave it. Back it with your own database.
type KeyStore interface {
	Get(customerID string) (ed25519.PublicKey, error)
	Put(customerID string, key ed25519.PublicKey) error
	Delete(customerID string) error
	// AdvanceLastEvent keeps the created time of the last event handled for the customer. It must be one atomic step, for example
	// UPDATE ... SET last_event = GREATEST(last_event, $2) ... RETURNING. If created is older than the kept time, it changes nothing and
	// returns false. Otherwise it keeps the newer of the two times and returns true. An equal time returns true: events of one second
	// cannot be put in order, and a retry of an event that failed must pass.
	AdvanceLastEvent(customerID string, created int64) (bool, error)
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
	mu    sync.Mutex
	keys  map[string]ed25519.PublicKey
	clock map[string]int64
}

// LastEvent is the time kept by AdvanceLastEvent, or 0 if none.
func (m *MemoryKeyStore) LastEvent(customerID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clock[customerID], nil
}

// AdvanceLastEvent is the KeyStore method.
func (m *MemoryKeyStore) AdvanceLastEvent(customerID string, created int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	last := m.clock[customerID]
	if created < last {
		return false, nil
	}
	if m.clock == nil {
		m.clock = map[string]int64{}
	}
	m.clock[customerID] = created
	return true, nil
}

func (m *MemoryKeyStore) Get(customerID string) (ed25519.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.keys[customerID]
	if !ok {
		return nil, ErrNoKey
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

func (m *MemoryKeyStore) Put(customerID string, key ed25519.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.set(customerID, key)
	return nil
}

// set stores a copy of the key. The caller holds the lock.
func (m *MemoryKeyStore) set(customerID string, key ed25519.PublicKey) {
	if m.keys == nil {
		m.keys = map[string]ed25519.PublicKey{}
	}
	m.keys[customerID] = append(ed25519.PublicKey(nil), key...)
}

// PutIfAbsent is the AtomicKeyStore method.
func (m *MemoryKeyStore) PutIfAbsent(customerID string, key ed25519.PublicKey) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[customerID]; ok {
		return false, nil
	}
	m.set(customerID, key)
	return true, nil
}

func (m *MemoryKeyStore) Delete(customerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, customerID)
	return nil
}

// ObserveOptions says how ObserveEvent treats an event that erases a key.
type ObserveOptions struct {
	// ApproveReset is called before a customer.reset or customer.deleted event erases the kept key. Return true only if you started the reset or
	// confirmed it with your own customer. The webhook is signed with a secret Custodian also holds, so the signature alone does not show that
	// the reset is real. If it is nil, resets are refused. If it returns an error, that error is returned and the key stays.
	ApproveReset func(customerID, eventType string) (bool, error)
}

// ObserveEvent is Observe with two more checks. Use it for every verified event.
//
// First it calls store.AdvanceLastEvent. If the event is older than the last one handled for the customer, it returns ErrStaleEvent and
// does nothing else, so a retried old event cannot pin an old key or erase a new one. The check and the update are one atomic store step,
// so two events at the same time cannot both pass. Events with the same created second cannot be put in order and are all handled.
//
// A customer.reset or customer.deleted event erases the kept key only if opts.ApproveReset says yes. Without that callback it returns
// ErrResetNotApproved and the key stays. The time is kept before this check, so a refused or failed event still counts as seen. A retry of
// the same event has the same time and is handled again.
func ObserveEvent(store KeyStore, event *webhook.Event, opts ObserveOptions) error {
	if event == nil {
		return ErrFormat
	}
	switch event.Type {
	case eventCustomerEnrolled, eventCustomerReset, eventCustomerDeleted:
	default:
		return nil
	}
	id, err := objectID(event.Data.Object)
	if err != nil {
		return err
	}
	fresh, err := store.AdvanceLastEvent(id, event.Created)
	if err != nil {
		return err
	}
	if !fresh {
		return ErrStaleEvent
	}
	if event.Type != eventCustomerEnrolled {
		if opts.ApproveReset == nil {
			return ErrResetNotApproved
		}
		ok, err := opts.ApproveReset(id, event.Type)
		if err != nil {
			return err
		}
		if !ok {
			return ErrResetNotApproved
		}
	}
	return Observe(store, event.Type, event.Data.Object)
}

// Observe keeps the signing key that a verified webhook event names. It trusts the vault: it asks no approval before a reset erases a key and
// does not check the order of events. Use ObserveEvent instead. Call it for every event, after webhook.ParseEvent. It acts on three types:
//
//	customer.enrolled: keeps the key. If you already hold another key for the customer it returns ErrKeyChanged and keeps the old one.
//	customer.reset, customer.deleted: forgets the key, so the next enrolment can set a new one.
//
// Any other type is ignored. The same event may arrive twice; that is harmless. If your store is an AtomicKeyStore, two events handled at
// the same time for one customer cannot both keep a key. Events for one customer can still arrive in another order than they were sent: keep
// the id of each handled event, as the webhook guide says.
func Observe(store KeyStore, eventType string, object json.RawMessage) error {
	switch eventType {
	case eventCustomerEnrolled:
		var o struct {
			ID           string `json:"id"`
			VaultSignKey string `json:"vault_sign_key"`
		}
		if err := json.Unmarshal(object, &o); err != nil || o.ID == "" {
			return ErrFormat
		}
		key, err := strict.DecodeString(o.VaultSignKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return ErrFormat
		}
		return pin(store, o.ID, key)
	case eventCustomerReset, eventCustomerDeleted:
		id, err := objectID(object)
		if err != nil {
			return err
		}
		return store.Delete(id)
	}
	return nil
}

func objectID(object json.RawMessage) (string, error) {
	var o struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(object, &o); err != nil || o.ID == "" {
		return "", ErrFormat
	}
	return o.ID, nil
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
	return errors.New("disclosure: the key store gave PutIfAbsent and Get answers that do not agree")
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
