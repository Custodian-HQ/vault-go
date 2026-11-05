package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type fixtureCase struct {
	Name       string            `json:"name"`
	Suite      string            `json:"suite"`
	PrivateKey string            `json:"business_private_key_hex"`
	PublicKey  string            `json:"business_public_key_hex"`
	KID        string            `json:"kid"`
	BusinessID string            `json:"business_id"`
	CustomerID string            `json:"customer_id"`
	RequestID  string            `json:"request_id"`
	Record     string            `json:"record"`
	ApprovedAt int64             `json:"approved_at"`
	SignKey    string            `json:"vault_sign_public_key_hex"`
	Keys       []string          `json:"keys"`
	Files      []string          `json:"files"`
	Fields     map[string]string `json:"fields"`
	FileGrants map[string]struct {
		FileID string `json:"file_id"`
		Key    string `json:"key_hex"`
	} `json:"file_grants"`
	Statement string          `json:"statement_cbor_hex"`
	Envelope  json.RawMessage `json:"envelope"`
	Refuse    []struct {
		Name     string          `json:"name"`
		Envelope json.RawMessage `json:"envelope"`
		Expected map[string]any  `json:"expected_override"`
		Error    string          `json:"error"`
	} `json:"refuse"`
}

func loadFixture(t *testing.T) []fixtureCase {
	t.Helper()
	raw, err := os.ReadFile("../testdata/fixtures/v1/disclosure-envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []fixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Cases
}

func (c fixtureCase) expected() Expected {
	private, _ := hex.DecodeString(c.PrivateKey)
	sign, _ := hex.DecodeString(c.SignKey)
	return Expected{RequestID: c.RequestID, BusinessID: c.BusinessID, CustomerID: c.CustomerID, KID: c.KID, Keys: c.Keys, Files: c.Files, SignKey: ed25519.PublicKey(sign), Suite: c.Suite, PrivateKey: private}
}

// The fixture comes from custodian-device-crypto, where the browser code made it. This reader was written separately, so a pass here is
// a second implementation agreeing with the first.
func TestTheEnvelopeTheBrowserSealedOpensForBothSuites(t *testing.T) {
	cases := loadFixture(t)
	if len(cases) != 4 {
		t.Fatalf("want two cases for each suite, one of them with files, got %d", len(cases))
	}
	withFiles := 0
	for _, c := range cases {
		got, err := OpenEnvelope(c.Envelope, c.expected())
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if got.Record != c.Record || got.ApprovedAt != c.ApprovedAt || len(got.Fields) != len(c.Fields) || len(got.Files) != len(c.FileGrants) {
			t.Errorf("%s: %+v", c.Name, got)
		}
		for k, v := range c.Fields {
			if got.Fields[k] != v {
				t.Errorf("%s: %s = %q, want %q", c.Name, k, got.Fields[k], v)
			}
		}
		for name, g := range c.FileGrants {
			if f := got.Files[name]; f.FileID != g.FileID || hex.EncodeToString(f.Key) != g.Key {
				t.Errorf("%s: file %s = %+v, want %+v", c.Name, name, f, g)
			}
		}
		if len(c.FileGrants) > 0 {
			withFiles++
		}
	}
	if withFiles != 2 {
		t.Errorf("want two cases with files, got %d", withFiles)
	}
}

func TestAFileOnlyRequestHasNoValuesAndTheKeysCanBeDiscarded(t *testing.T) {
	c := loadFixture(t)[3]
	if len(c.Keys) != 0 || len(c.Files) != 1 {
		t.Fatalf("%s is not the file-only case", c.Name)
	}
	got, err := OpenEnvelope(c.Envelope, c.expected())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Fields) != 0 || len(got.Files["passport"].Key) != 32 {
		t.Fatalf("%+v", got)
	}
	got.Discard()
	if !bytes.Equal(got.Files["passport"].Key, make([]byte, 32)) {
		t.Error("Discard left the file key in place")
	}
}

func TestANameAskedForTwiceIsRefusedBeforeAnythingIsOpened(t *testing.T) {
	c := loadFixture(t)[2]
	want := c.expected()
	want.Keys = append(want.Keys, want.Files[0])
	if _, err := OpenEnvelope(c.Envelope, want); !errors.Is(err, ErrPayload) {
		t.Errorf("a name in both groups: %v", err)
	}
}

func TestTheStatementIsRebuiltByteForByte(t *testing.T) {
	for _, c := range loadFixture(t) {
		var w wire
		if err := json.Unmarshal(c.Envelope, &w); err != nil {
			t.Fatal(err)
		}
		enc, _ := strict.DecodeString(w.Enc)
		commit, _ := strict.DecodeString(w.Commit)
		ct, _ := strict.DecodeString(w.CT)
		statement := encodeMap([]pair{
			{text("v"), uint_(uint64(w.V))}, {text("suite"), text(w.Suite)}, {text("request_id"), text(w.RequestID)}, {text("business_id"), text(w.BusinessID)},
			{text("customer_id"), text(w.CustomerID)}, {text("kid"), text(w.KID)}, {text("enc"), bstr(enc)}, {text("commit"), bstr(commit)}, {text("ct"), bstr(ct)},
		})
		if hex.EncodeToString(statement) != c.Statement {
			t.Errorf("%s: the rebuilt statement differs from the one the browser signed", c.Name)
		}
	}
}

func TestEveryRefusalInTheFixtureIsRefusedForTheRightReason(t *testing.T) {
	names := map[string]error{"format": ErrFormat, "request": ErrRequest, "business": ErrBusiness, "customer": ErrCustomer, "key": ErrKey, "signature": ErrSignature, "payload": ErrPayload}
	for _, c := range loadFixture(t) {
		if len(c.Refuse) < 10 {
			t.Fatalf("%s: the fixture lists %d refusals", c.Name, len(c.Refuse))
		}
		for _, r := range c.Refuse {
			want := c.expected()
			if v, ok := r.Expected["business_id"].(string); ok {
				want.BusinessID = v
			}
			if v, ok := r.Expected["customer_id"].(string); ok {
				want.CustomerID = v
			}
			if v, ok := r.Expected["kid"].(string); ok {
				want.KID = v
			}
			if v, ok := r.Expected["vault_sign_public_key_hex"].(string); ok {
				want.SignKey, _ = hex.DecodeString(v)
			}
			if v, ok := r.Expected["keys"].([]any); ok {
				want.Keys = nil
				for _, k := range v {
					want.Keys = append(want.Keys, k.(string))
				}
			}
			if v, ok := r.Expected["files"].([]any); ok {
				want.Files = nil
				for _, k := range v {
					want.Files = append(want.Files, k.(string))
				}
			}
			if _, err := OpenEnvelope(r.Envelope, want); !errors.Is(err, names[r.Error]) {
				t.Errorf("%s / %s: want %s, got %v", c.Name, r.Name, r.Error, err)
			}
		}
	}
}

func TestOnlyTheOwnerOfTheKeyCanOpen(t *testing.T) {
	c := loadFixture(t)[1]
	want := c.expected()
	other, _, err := GenerateKey(SuiteClassic)
	if err != nil {
		t.Fatal(err)
	}
	want.PrivateKey = other
	if _, err := OpenEnvelope(c.Envelope, want); !errors.Is(err, ErrPayload) {
		t.Errorf("another private key: %v", err)
	}
	want = c.expected()
	want.PrivateKey = []byte("short")
	if _, err := OpenEnvelope(c.Envelope, want); !errors.Is(err, ErrKey) {
		t.Errorf("a private key that is not one: %v", err)
	}
}

func TestTheCBORReaderRefusesWhatIsNotDeterministic(t *testing.T) {
	for name, raw := range map[string][]byte{
		"a number that is not the shortest": {0x18, 0x05},
		"an indefinite text":                {0x7f, 0x61, 0x61, 0xff},
		"a map with keys out of order":      {0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02},
		"a map with a repeated key":         {0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02},
		"bytes after the item":              {0x01, 0x00},
		"a tag":                             {0xc1, 0x01},
		"a float":                           {0xf9, 0x3c, 0x00},
		"text that is not UTF-8":            {0x62, 0xff, 0xfe},
		"a truncated item":                  {0x62, 0x61},
	} {
		if _, err := decode(raw); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	if v, err := decode([]byte{0xa1, 0x61, 0x61, 0x01}); err != nil || v.kind != 'm' || v.m[0].val.num != 1 {
		t.Errorf("a good map: %+v %v", v, err)
	}
}
