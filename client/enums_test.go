package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// specLists reads every list of values that the vendored API spec gives to a purpose, status or state, each as a sorted text.
func specLists(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../testdata/openapi-vault.yaml")
	if err != nil {
		t.Fatal(err)
	}
	lists := map[string]bool{}
	for _, m := range regexp.MustCompile(`\b(?:purpose|status|state): \{ type: string, enum: \[([^\]]+)\] \}`).FindAllStringSubmatch(string(raw), -1) {
		lists[sortedJoin(strings.Split(strings.ReplaceAll(m[1], "'", ""), ","))] = true
	}
	return lists
}

func sortedJoin(names []string) string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, strings.TrimSpace(n))
	}
	sort.Strings(out)
	return strings.Join(out, "|")
}

func names[T ~string](values []T) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, string(v))
	}
	return out
}

func TestEnumsAreExactlyThoseOfTheSpec(t *testing.T) {
	ours := map[string][]string{
		"Purpose":               names(Purposes()),
		"SessionStatus":         names(SessionStatuses()),
		"DisclosureStatus":      names(DisclosureStatuses()),
		"DisclosureKeyStatus":   names(DisclosureKeyStatuses()),
		"WebhookEndpointStatus": names(WebhookEndpointStatuses()),
		"WebhookDeliveryStatus": names(WebhookDeliveryStatuses()),
		"CustomerState":         names(CustomerStates()),
	}
	spec := specLists(t)
	if len(spec) < 5 {
		t.Fatalf("the spec gave only %d lists", len(spec))
	}
	have := map[string]bool{}
	for name, list := range ours {
		joined := sortedJoin(list)
		have[joined] = true
		if !spec[joined] {
			t.Errorf("%s is not a list of the spec: %s", name, joined)
		}
		seen := map[string]bool{}
		for _, v := range list {
			if seen[v] {
				t.Errorf("%s lists %q twice", name, v)
			}
			seen[v] = true
		}
	}
	for list := range spec {
		if !have[list] {
			t.Errorf("the spec has a list that the SDK lacks: %s", list)
		}
	}
}

func TestEnumValid(t *testing.T) {
	if !PurposeRecoverySettings.Valid() || !Purpose("enrol").Valid() || Purpose("device_link").Valid() || Purpose("").Valid() {
		t.Fatal("Purpose.Valid is wrong")
	}
	if !SessionCompleted.Valid() || SessionStatus("done").Valid() {
		t.Fatal("SessionStatus.Valid is wrong")
	}
	if !CustomerResetEnrolmentNeeded.Valid() || CustomerState("reset").Valid() {
		t.Fatal("CustomerState.Valid is wrong")
	}
}

func TestEnumsAreSentAndReadAsText(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		_, _ = w.Write([]byte(`{"id":"ses_1","purpose":"recovery_settings","status":"created"}`))
	}))
	defer srv.Close()
	session, err := mustClient(t, srv.URL).CreateSession(context.Background(), CreateSessionParams{Customer: "cus_1", Purpose: PurposeRecoverySettings, ReturnURL: "https://a.example/x", State: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if body["purpose"] != "recovery_settings" || session.Purpose != PurposeRecoverySettings || session.Status != SessionCreated {
		t.Fatalf("sent %v, got %q and %q", body["purpose"], session.Purpose, session.Status)
	}
}
