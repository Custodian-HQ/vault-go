package custodian

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are vendored from custodian-device-crypto. Two checks keep them honest: every file must match the
// manifest, and the manifest must match the hash pinned in testdata/fixtures.lock. To take new fixtures, run
// scripts/vendor-fixtures.sh and review the diff. PROVENANCE.md is this repository's own text, so only its name is checked.
const dir = "testdata/fixtures/v1"

func sha(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestManifestIsThePinnedOne(t *testing.T) {
	pinned, err := os.ReadFile("testdata/fixtures.lock")
	if err != nil {
		t.Fatal(err)
	}
	if got := sha(t, filepath.Join(dir, "MANIFEST.json")); got != strings.TrimSpace(string(pinned)) {
		t.Fatalf("MANIFEST.json is %s but %s is pinned", got, strings.TrimSpace(string(pinned)))
	}
}

func TestEveryFixtureMatchesTheManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Files map[string]string }
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() == "MANIFEST.json" {
			continue
		}
		want, listed := manifest.Files[e.Name()]
		if !listed {
			t.Errorf("%s is not in the manifest", e.Name())
		} else if e.Name() == "PROVENANCE.md" {
			continue
		} else if got := sha(t, filepath.Join(dir, e.Name())); got != want {
			t.Errorf("%s changed: %s, manifest says %s", e.Name(), got, want)
		}
	}
	for name := range manifest.Files {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s is in the manifest but missing", name)
		}
	}
}
