package client

import (
	"crypto/subtle"
	"errors"
	"net/url"
	"strings"
)

// ErrBadReturn means the address the customer came back to cannot be used.
var ErrBadReturn = errors.New("custodian: the return address is not valid for this request")

// ParseReturn reads the address the vault sent the customer back to and returns the session id.
//
// It trusts nothing in the address except the session id, and only when `state` is the exact value your server issued
// for this signed-in user. A `status` or any other parameter is ignored: anyone can type one. After this, call the
// API for the session (`sessions.retrieve`) or wait for the webhook to learn what really happened.
func ParseReturn(returnURL, expectedState string) (sessionID string, err error) {
	if expectedState == "" {
		return "", ErrBadReturn
	}
	u, err := url.Parse(returnURL)
	if err != nil {
		return "", ErrBadReturn
	}
	q := u.Query()
	sessions, states := q["session"], q["state"]
	if len(sessions) != 1 || len(states) != 1 || sessions[0] == "" {
		return "", ErrBadReturn
	}
	if subtle.ConstantTimeCompare([]byte(states[0]), []byte(expectedState)) != 1 {
		return "", ErrBadReturn
	}
	return sessions[0], nil
}

// ErrBadFingerprint means the fingerprint is not 64 hexadecimal characters.
var ErrBadFingerprint = errors.New("custodian: the fingerprint must be 64 hexadecimal characters")

// ApproveURL adds your disclosure key's fingerprint to the link of an approve session, in the fragment, so that it never reaches the vault's
// server. Take the fingerprint from your own app configuration (disclosure.Fingerprint of your key), not from the vault: the hosted page
// compares it with the key the vault gives it, and stops the request if they differ. That check is what tells the customer the request is yours.
func ApproveURL(sessionURL, fingerprint string) (string, error) {
	if len(fingerprint) != 64 {
		return "", ErrBadFingerprint
	}
	for _, c := range fingerprint {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", ErrBadFingerprint
		}
	}
	u, err := url.Parse(sessionURL)
	if err != nil || u.Fragment == "" || !(u.Scheme == "https" || u.Scheme == "http" && u.Hostname() == "localhost") {
		return "", ErrBadReturn
	}
	return sessionURL + "&fp=" + strings.ToLower(fingerprint), nil
}
