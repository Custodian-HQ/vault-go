package custodian

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Founder rule: this SDK never carries Custodian Personal code. The needles are built in pieces so this file does not match itself.
func TestNoPersonalCodeOrFixtureIsHere(t *testing.T) {
	needles := []string{"cdv/v1/" + "personal/", "fixtures/" + "personal", "personal-" + "sign.json"}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.Contains(strings.ToLower(path), "personal") && path != "personal_guard_test.go" {
			t.Errorf("%s has a Personal name", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range needles {
			if strings.Contains(string(data), n) {
				t.Errorf("%s holds Personal text %q", path, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
