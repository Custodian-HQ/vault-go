package client

import "testing"

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
