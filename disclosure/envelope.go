package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
)

// The reasons OpenEnvelope refuses an envelope. Check them with errors.Is.
var (
	ErrFormat    = errors.New("disclosure: the envelope is damaged or has the wrong shape")
	ErrRequest   = errors.New("disclosure: the envelope is for another request")
	ErrBusiness  = errors.New("disclosure: the envelope is for another business")
	ErrCustomer  = errors.New("disclosure: the envelope is for another customer")
	ErrKey       = errors.New("disclosure: the envelope was sealed to another key")
	ErrSignature = errors.New("disclosure: the customer signature is not valid")
	ErrPayload   = errors.New("disclosure: the sealed content is not what was approved")
)

const (
	envelopeVersion = 2
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
	// Keys are the value names you asked for and Files the file names. The envelope must hold exactly these, each in its own group.
	// A request may ask for values only, files only, or both.
	Keys  []string
	Files []string
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
	// Files holds a grant for each file you asked for. Download the file with client.DownloadDisclosedFile and decrypt it with
	// Opened.OpenFile. A key opens that one file only and the customer cannot take it back: use the file, then discard the key.
	Files map[string]File

	businessID, customerID string
}

// File is the grant for one disclosed file: the file id and its 32-byte file key.
type File struct {
	FileID string
	Key    []byte
}

const fileKeySize = 32

// fileKeyID is the first 8 bytes of SHA-256("cdv/v1/file-key"): it says which key derivation made the file key.
var fileKeyID = func() []byte { sum := sha256.Sum256([]byte("cdv/v1/file-key")); return sum[:8] }()

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
// the same request and holds exactly the values and files you asked for. Nothing is opened unless the signature is good. Download the
// files you need before you call AckDisclosure: the vault serves them only while the envelope exists.
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

	kem, err := kemFor(want.Suite)
	if err != nil {
		return nil, ErrKey
	}
	key, err := kem.NewPrivateKey(want.PrivateKey)
	if err != nil {
		return nil, ErrKey
	}
	// The key is named from your own private key, so an envelope sealed to any other key fails the signature below.
	rk := Fingerprint(want.Suite, key.PublicKey().Bytes())

	statement := encodeMap([]pair{
		{text("v"), uint_(uint64(w.V))}, {text("suite"), text(w.Suite)}, {text("request_id"), text(w.RequestID)}, {text("business_id"), text(w.BusinessID)},
		{text("customer_id"), text(w.CustomerID)}, {text("kid"), text(w.KID)}, {text("rk"), text(rk)}, {text("enc"), bstr(enc)}, {text("commit"), bstr(commit)}, {text("ct"), bstr(ct)},
	})
	message := append(append([]byte(signatureLabel), 0), statement...)
	if len(want.SignKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(want.SignKey, message, sig) {
		return nil, ErrSignature
	}

	names := append(append([]string{}, want.Keys...), want.Files...)
	// Key names are ASCII, so sorting the strings sorts their bytes.
	sort.Strings(names)
	for i := 1; i < len(names); i++ {
		if names[i] == names[i-1] {
			return nil, ErrPayload
		}
	}
	aad := encodeTextArray(names)
	info := append(append(append([]byte(infoLabel), 0), w.BusinessID...), append(append([]byte{0}, w.RequestID...), append([]byte{0}, rk...)...)...)

	plain, err := Open(want.Suite, want.PrivateKey, enc, info, aad, ct, commit)
	if err != nil {
		return nil, ErrPayload
	}
	defer clear(plain)
	return readPayload(plain, want)
}

func readPayload(plain []byte, want Expected) (_ *Opened, err error) {
	v, err := decode(plain)
	if err != nil || v.kind != 'm' {
		return nil, ErrPayload
	}
	out := &Opened{Fields: map[string]string{}, Files: map[string]File{}, businessID: want.BusinessID, customerID: want.CustomerID}
	defer func() {
		if err != nil {
			out.Discard()
		}
	}()
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
		case "files":
			// A writer leaves "files" out when no file is disclosed, so an empty map is refused.
			if e.val.kind != 'm' || len(e.val.m) == 0 {
				return nil, ErrPayload
			}
			for _, f := range e.val.m {
				grant, ok := readGrant(f.val)
				if !ok {
					return nil, ErrPayload
				}
				out.Files[f.key] = grant
			}
		default:
			return nil, ErrPayload
		}
	}
	if !seenRequest || !seenRecord || !seenAt || !seenFields || !holdsExactly(out.Fields, want.Keys) || !holdsExactly(out.Files, want.Files) {
		return nil, ErrPayload
	}
	return out, nil
}

func readGrant(v value) (File, bool) {
	if v.kind != 'm' || len(v.m) != 3 {
		return File{}, false
	}
	var g File
	var keyID []byte
	for _, e := range v.m {
		switch {
		case e.key == "file_id" && e.val.kind == 's':
			g.FileID = e.val.str
		case e.key == "key" && e.val.kind == 'b':
			g.Key = e.val.raw
		case e.key == "key_id" && e.val.kind == 'b':
			keyID = e.val.raw
		default:
			return File{}, false
		}
	}
	if g.FileID == "" || len(g.Key) != fileKeySize || !bytes.Equal(keyID, fileKeyID) {
		return File{}, false
	}
	g.Key = bytes.Clone(g.Key)
	return g, true
}

func holdsExactly[V any](got map[string]V, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			return false
		}
	}
	return true
}

// Discard clears the file keys of every grant. Call it once you have the files you need. A key cannot be taken back, so a key you do not
// keep is a key that cannot leak. Values in Fields are Go strings and cannot be cleared.
func (o *Opened) Discard() {
	for _, f := range o.Files {
		clear(f.Key)
	}
}
