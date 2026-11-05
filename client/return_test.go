package client

import (
	"strings"
	"testing"
)

func TestParseReturn(t *testing.T) {
	cases := []struct {
		name, url, state, want string
		ok                     bool
	}{
		{"a good return", "https://shop.example.com/done?session=ses_1&state=abc", "abc", "ses_1", true},
		{"a status that someone added is ignored", "https://shop.example.com/done?session=ses_1&state=abc&status=completed", "abc", "ses_1", true},
		{"a status alone proves nothing", "https://shop.example.com/done?status=completed", "abc", "", false},
		{"a state the server did not issue", "https://shop.example.com/done?session=ses_1&state=zzz", "abc", "", false},
		{"no state expected", "https://shop.example.com/done?session=ses_1&state=", "", "", false},
		{"a missing session", "https://shop.example.com/done?state=abc", "abc", "", false},
		{"two sessions", "https://shop.example.com/done?session=ses_1&session=ses_2&state=abc", "abc", "", false},
		{"two states", "https://shop.example.com/done?session=ses_1&state=abc&state=abc", "abc", "", false},
		{"not an address", "%zz", "abc", "", false},
	}
	for _, c := range cases {
		got, err := ParseReturn(c.url, c.state)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%s: got %q, %v", c.name, got, err)
		}
	}
}

func TestApproveURLOnlyTakesHTTPSOrHTTPOnLocalhost(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	for name, c := range map[string]struct {
		url string
		ok  bool
	}{
		"https":                      {"https://vault.example/b/o/approve#st=t", true},
		"http on localhost":          {"http://localhost/b/o/approve#st=t", true},
		"http on localhost and port": {"http://localhost:3000/b/o/approve#st=t", true},
		"http on a real host":        {"http://vault.example/b/o/approve#st=t", false},
		"http on a loopback address": {"http://127.0.0.1/b/o/approve#st=t", false},
		"javascript on localhost":    {"javascript://localhost/%0Aalert(1)#x", false},
		"ftp on localhost":           {"ftp://localhost/x#a", false},
		"file on localhost":          {"file://localhost/x#a", false},
		"no scheme":                  {"//localhost/x#a", false},
	} {
		got, err := ApproveURL(c.url, fp)
		if (err == nil) != c.ok || (c.ok && got != c.url+"&fp="+fp) {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
}
