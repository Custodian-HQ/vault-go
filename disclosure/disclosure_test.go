package disclosure

import (
	"bytes"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

const fixtures = "../testdata/fixtures/v1/"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(fixtures + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

// The sample was sealed by custodian-device-crypto. Opening it here proves the two implementations agree.
func TestOpensTheSampleSealedByTheCryptoRepository(t *testing.T) {
	var s struct{ Suite, SkR, Info, Aad, Enc, Ct, Commit, Pt string }
	readJSON(t, "hpke-xwing-aes256gcm-sample.json", &s)
	got, err := Open(s.Suite, mustHex(t, s.SkR), mustHex(t, s.Enc), mustHex(t, s.Info), mustHex(t, s.Aad), mustHex(t, s.Ct), mustHex(t, s.Commit))
	if err != nil || !bytes.Equal(got, mustHex(t, s.Pt)) {
		t.Fatalf("sample did not open: %v", err)
	}

	bad := mustHex(t, s.Commit)
	bad[0] ^= 1
	if _, err := Open(s.Suite, mustHex(t, s.SkR), mustHex(t, s.Enc), mustHex(t, s.Info), mustHex(t, s.Aad), mustHex(t, s.Ct), bad); err != ErrCommitment {
		t.Errorf("a wrong commitment must be refused, got %v", err)
	}
}

func TestHybridKeyMatchesThePublishedVector(t *testing.T) {
	var v struct{ SkRm, PkRm string }
	readJSON(t, "hpke-xwing-vector.json", &v)
	key, err := hpke.MLKEM768X25519().NewPrivateKey(mustHex(t, v.SkRm))
	if err != nil || !bytes.Equal(key.PublicKey().Bytes(), mustHex(t, v.PkRm)) {
		t.Fatalf("seed does not give the vector's public key: %v", err)
	}
}

func TestEverySuiteHasAKeyPairThatRoundTrips(t *testing.T) {
	for _, suite := range []string{SuiteHybrid, SuiteClassic} {
		private, public, err := GenerateKey(suite)
		if err != nil {
			t.Fatal(err)
		}
		kem, _ := kemFor(suite)
		pub, err := kem.NewPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		enc, sender, err := hpke.NewSender(pub, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("i"))
		if err != nil {
			t.Fatal(err)
		}
		ct, _ := sender.Seal([]byte("a"), []byte("hello"))
		commit, _ := sender.Export(commitLabel, commitSize)
		got, err := Open(suite, private, enc, []byte("i"), []byte("a"), ct, commit)
		if err != nil || string(got) != "hello" {
			t.Errorf("%s: %q, %v", suite, got, err)
		}
	}
}

func TestAnUnknownSuiteIsRefused(t *testing.T) {
	if _, _, err := GenerateKey("nope"); err == nil {
		t.Error("an unknown suite must be refused")
	}
}

func TestFingerprint_MatchesTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(fixtures + "disclosure-key-fingerprint.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Label string `json:"label"`
		Cases []struct {
			Name        string `json:"name"`
			Suite       string `json:"suite"`
			PublicKey   string `json:"public_key_hex"`
			Fingerprint string `json:"fingerprint"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Label != "cdv/v1/dkfp" || len(fixture.Cases) < 4 {
		t.Fatalf("unexpected fixture: %+v", fixture)
	}
	for _, c := range fixture.Cases {
		if got := Fingerprint(c.Suite, mustHex(t, c.PublicKey)); got != c.Fingerprint {
			t.Errorf("%s: got %s, want %s. Every implementation must give the same answer", c.Name, got, c.Fingerprint)
		}
	}
}
