package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
)

// The reasons OpenEnvelope refuses an envelope. Check them with errors.Is.
var (
	ErrFormat    = errors.New("disclosure: the envelope is not well formed")
	ErrRequest   = errors.New("disclosure: the envelope is for another request")
	ErrBusiness  = errors.New("disclosure: the envelope is for another business")
	ErrCustomer  = errors.New("disclosure: the envelope is for another customer")
	ErrKey       = errors.New("disclosure: the envelope was sealed to another key")
	ErrSignature = errors.New("disclosure: the signature does not check")
	ErrPayload   = errors.New("disclosure: the sealed content is not what was approved")
)

const (
	envelopeVersion = 1
	signatureLabel  = "cdv/v1/sig-disclosure"
	infoLabel       = "cdv/v1/disclosure"
)

// Expected is what you know before you open an envelope. OpenEnvelope checks all of it.
type Expected struct {
	// RequestID is the disclosure request (dsc_...). BusinessID is your organization's public id (org_...), CustomerID the customer (cus_...)
	// and KID the id of your disclosure key that the request was made with.
	RequestID  string
	BusinessID string
	CustomerID string
	KID        string
	// Keys are the key names you asked for. The envelope must hold exactly these.
	Keys []string
	// SignKey is the customer's public vault-sign key. Use the one you kept from the customer.enrolled webhook.
	SignKey ed25519.PublicKey
	// Suite and PrivateKey are your disclosure key.
	Suite      string
	PrivateKey []byte
}

// Opened is what the customer approved.
type Opened struct {
	// Record is the token of the record the values came from.
	Record     string
	ApprovedAt int64
	Fields     map[string]string
}

type wire struct {
	V          int    `json:"v"`
	Suite      string `json:"suite"`
	RequestID  string `json:"request_id"`
	BusinessID string `json:"business_id"`
	CustomerID string `json:"customer_id"`
	KID        string `json:"kid"`
	Enc        string `json:"enc"`
	Commit     string `json:"commit"`
	CT         string `json:"ct"`
	Sig        string `json:"sig"`
}

var strict = base64.RawURLEncoding.Strict()

// OpenEnvelope checks and opens an envelope from GET /disclosures/{id}/envelope. It checks, in order: the shape; the request, the business,
// the customer, the key and the suite; the customer's signature over everything; the key commitment; and that the sealed content names
// the same request and holds exactly the keys you asked for. Nothing is opened unless the signature is good. Call AckDisclosure afterwards.
func OpenEnvelope(raw []byte, want Expected) (*Opened, error) {
	var w wire
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || w.V != envelopeVersion {
		return nil, ErrFormat
	}
	var enc, commit, ct, sig []byte
	for _, f := range []struct {
		to *[]byte
		s  string
	}{{&enc, w.Enc}, {&commit, w.Commit}, {&ct, w.CT}, {&sig, w.Sig}} {
		b, err := strict.DecodeString(f.s)
		if err != nil {
			return nil, ErrFormat
		}
		*f.to = b
	}
	switch {
	case w.RequestID != want.RequestID:
		return nil, ErrRequest
	case w.BusinessID != want.BusinessID:
		return nil, ErrBusiness
	case w.CustomerID != want.CustomerID:
		return nil, ErrCustomer
	case w.KID != want.KID || w.Suite != want.Suite:
		return nil, ErrKey
	}

	statement := encodeMap([]pair{
		{text("v"), uint_(uint64(w.V))}, {text("suite"), text(w.Suite)}, {text("request_id"), text(w.RequestID)}, {text("business_id"), text(w.BusinessID)},
		{text("customer_id"), text(w.CustomerID)}, {text("kid"), text(w.KID)}, {text("enc"), bstr(enc)}, {text("commit"), bstr(commit)}, {text("ct"), bstr(ct)},
	})
	message := append(append([]byte(signatureLabel), 0), statement...)
	if len(want.SignKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(want.SignKey, message, sig) {
		return nil, ErrSignature
	}

	names := append([]string{}, want.Keys...)
	// Key names are ASCII, so sorting the strings sorts their bytes.
	sort.Strings(names)
	aad := encodeTextArray(names)
	info := append(append(append([]byte(infoLabel), 0), w.BusinessID...), append([]byte{0}, w.RequestID...)...)

	kem, err := kemFor(want.Suite)
	if err != nil {
		return nil, ErrKey
	}
	key, err := kem.NewPrivateKey(want.PrivateKey)
	if err != nil {
		return nil, ErrKey
	}
	recipient, err := hpke.NewRecipient(enc, key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, ErrPayload
	}
	expected, err := recipient.Export(commitLabel, commitSize)
	if err != nil || subtle.ConstantTimeCompare(expected, commit) != 1 {
		return nil, ErrPayload
	}
	plain, err := recipient.Open(aad, ct)
	if err != nil {
		return nil, ErrPayload
	}
	return readPayload(plain, want)
}

func readPayload(plain []byte, want Expected) (*Opened, error) {
	v, err := decode(plain)
	if err != nil || v.kind != 'm' {
		return nil, ErrPayload
	}
	out := &Opened{Fields: map[string]string{}}
	var seenRequest, seenRecord, seenAt, seenFields bool
	for _, e := range v.m {
		switch e.key {
		case "request_id":
			if e.val.kind != 's' || e.val.str != want.RequestID {
				return nil, ErrPayload
			}
			seenRequest = true
		case "record":
			if e.val.kind != 's' || e.val.str == "" {
				return nil, ErrPayload
			}
			out.Record, seenRecord = e.val.str, true
		case "approved_at":
			if e.val.kind != 'n' || e.val.num > 1<<62 {
				return nil, ErrPayload
			}
			out.ApprovedAt, seenAt = int64(e.val.num), true
		case "fields":
			if e.val.kind != 'm' {
				return nil, ErrPayload
			}
			for _, f := range e.val.m {
				if f.val.kind != 's' {
					return nil, ErrPayload
				}
				out.Fields[f.key] = f.val.str
			}
			seenFields = true
		default:
			return nil, ErrPayload
		}
	}
	if !seenRequest || !seenRecord || !seenAt || !seenFields || len(out.Fields) != len(want.Keys) {
		return nil, ErrPayload
	}
	for _, k := range want.Keys {
		if _, ok := out.Fields[k]; !ok {
			return nil, ErrPayload
		}
	}
	return out, nil
}
