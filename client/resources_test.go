package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// specOperations reads "METHOD /path" for every operation in the vendored business API spec.
func specOperations(t *testing.T) map[string]*regexp.Regexp {
	t.Helper()
	raw, err := os.ReadFile("../testdata/openapi-vault.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pinned, _ := os.ReadFile("../testdata/openapi-vault.lock")
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != strings.TrimSpace(string(pinned)) {
		t.Fatal("testdata/openapi-vault.yaml is not the pinned spec: run scripts/vendor-spec.sh and review the diff")
	}
	operations := map[string]*regexp.Regexp{}
	inPaths, path := false, ""
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && line != "" && !strings.HasPrefix(line, " "):
			inPaths = false
		case inPaths && strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":"):
			path = strings.TrimSuffix(strings.TrimSpace(line), ":")
		case inPaths && regexp.MustCompile(`^    (get|post|put|patch|delete):$`).MatchString(line):
			method := strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(line), ":"))
			pattern := regexp.MustCompile(`\\\{[^}]+\\\}`).ReplaceAllString(regexp.QuoteMeta(path), `[^/]+`)
			operations[method+" "+path] = regexp.MustCompile(`^` + pattern + `$`)
		}
	}
	if len(operations) < 20 {
		t.Fatalf("read only %d operations from the spec: the reader is broken", len(operations))
	}
	return operations
}

// TestEverySDKMethodMatchesTheSpecAndTheSpecIsFullyCovered is the drift guard: the SDK may call only operations the spec has,
// and must have a method for every operation the spec has.
func TestEverySDKMethodMatchesTheSpecAndTheSpecIsFullyCovered(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodDelete || strings.HasSuffix(r.URL.Path, "/retry") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	ctx := context.Background()

	_, _ = c.Me(ctx)
	_, _ = c.CreateCustomer(ctx, "ref")
	_, _ = c.GetCustomer(ctx, "cus_1")
	_ = c.DeleteCustomer(ctx, "cus_1")
	_, _ = c.ResetCustomer(ctx, "cus_1", "https://a.example/x", "s")
	_, _ = c.ListCustomers(ctx, ListCustomersParams{Limit: 5, StartingAfter: "cus_1", ExternalRef: "x", State: "reset: enrolment needed"})
	_, _ = c.GetResetContactText(ctx)
	_, _ = c.SetResetContactText(ctx, "Call us")
	_, _ = c.CreateSession(ctx, CreateSessionParams{Customer: "cus_1", Purpose: PurposeEnrol, ReturnURL: "https://a.example/x", State: "s"})
	_, _ = c.GetSession(ctx, "ses_1")
	_, _ = c.ListRecords(ctx, ListRecordsParams{Customer: "cus_1", Limit: 5, StartingAfter: "rec_1"})
	_, _ = c.GetRecord(ctx, "rec_1")
	_, _ = c.ListTemplates(ctx)
	_, _ = c.CreateTemplate(ctx, Template{Name: "kyc", Keys: []Key{{Name: "a"}}})
	_, _ = c.GetTemplate(ctx, "kyc")
	_, _ = c.ReplaceTemplate(ctx, "kyc", []Key{{Name: "b"}})
	_ = c.DeleteTemplate(ctx, "kyc")
	_, _ = c.GetRecoveryPolicy(ctx)
	_, _ = c.SetRecoveryPolicy(ctx, 3)
	_, _ = c.ListWebhookEndpoints(ctx)
	_, _ = c.ListWebhookDeliveries(ctx, ListDeliveriesParams{Endpoint: "we_1", Limit: 5, StartingAfter: 9})
	_ = c.RetryWebhookDelivery(ctx, 7)
	_, _ = c.ListDisclosureKeys(ctx)
	_, _ = c.CreateDisclosure(ctx, CreateDisclosureParams{Record: "rec_1", Keys: []string{"a"}, Reason: "r", Fingerprint: "f"})
	_, _ = c.GetDisclosure(ctx, "dsc_1")
	_, _ = c.ListDisclosures(ctx, ListDisclosuresParams{Status: "pending", Limit: 5, StartingAfter: "dsc_1"})
	_, _ = c.CancelDisclosure(ctx, "dsc_1")
	_, _ = c.GetDisclosureEnvelope(ctx, "dsc_1")
	if body, err := c.DownloadDisclosedFile(ctx, "dsc_1", "passport", DownloadFileParams{}); err == nil {
		body.Close()
	}
	_, _ = c.AckDisclosure(ctx, "dsc_1")
	_, _ = c.GetUsage(ctx, time.Time{}, time.Time{})
	_, _ = c.ListAuditEvents(ctx, 5, 9)

	operations := specOperations(t)
	covered := map[string]bool{}
	for _, call := range seen {
		method, path, _ := strings.Cut(call, " ")
		matched := false
		for key, pattern := range operations {
			if strings.HasPrefix(key, method+" ") && pattern.MatchString(path) {
				matched, covered[key] = true, true
			}
		}
		if !matched {
			t.Errorf("the SDK calls %s, which the spec does not have", call)
		}
	}
	var missing []string
	for key := range operations {
		if !covered[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the spec has operations with no SDK method: %v", missing)
	}
}

func TestResourceMethodsSendAndReadTheRightShapes(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		gotMethod, gotPath, gotQuery, gotBody = r.Method, r.URL.Path, r.URL.RawQuery, string(body)
		switch {
		case r.URL.Path == "/sessions":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"ses_1","customer":"cus_1","purpose":"enrol","status":"created","livemode":false,"return_url":"https://a.example/x","state":"s","expires_at":"2026-10-24T12:00:00Z","created_at":"2026-10-24T11:45:00Z","url":"https://vault.example/b/org_x/enrol#st=tok"}`))
		case strings.HasPrefix(r.URL.Path, "/customers/"):
			w.Write([]byte(`{"id":"cus_1","external_ref":"u","livemode":true,"state":"active","enrolled":true,"created_at":"2026-10-24T11:45:00Z"}`))
		default:
			w.Write([]byte(`{"data":[{"id":4,"endpoint":"we_1","event":"evt_1","type":"session.expired","status":"delivered","attempts":1,"last_status":200,"created_at":"2026-10-24T11:45:00Z"}]}`))
		}
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	ctx := context.Background()

	session, err := c.CreateSession(ctx, CreateSessionParams{Customer: "cus_1", Purpose: PurposeEntry, ReturnURL: "https://a.example/x", State: "s", Keys: []Key{{Name: "id_document", Type: "file"}}})
	if err != nil || session.URL == "" || session.Status != "created" || session.ExpiresAt.IsZero() {
		t.Fatalf("session: %+v %v", session, err)
	}
	if gotMethod != "POST" || gotPath != "/sessions" || !strings.Contains(gotBody, `"return_url":"https://a.example/x"`) || !strings.Contains(gotBody, `"keys":[{"name":"id_document","type":"file"}]`) || strings.Contains(gotBody, "template") {
		t.Errorf("unexpected request: %s %s %s", gotMethod, gotPath, gotBody)
	}
	customer, err := c.GetCustomer(ctx, "cus_1")
	if err != nil || !customer.Enrolled || customer.ExternalRef != "u" {
		t.Errorf("customer: %+v %v", customer, err)
	}
	deliveries, err := c.ListWebhookDeliveries(ctx, ListDeliveriesParams{Endpoint: "we_1", Limit: 5, StartingAfter: 9})
	if err != nil || len(deliveries) != 1 || deliveries[0].LastStatus == nil || *deliveries[0].LastStatus != 200 {
		t.Errorf("deliveries: %+v %v", deliveries, err)
	}
	if gotQuery != "endpoint=we_1&limit=5&starting_after=9" {
		t.Errorf("unexpected query: %s", gotQuery)
	}
}

func TestDisclosureMethodsSendAndReadTheRightShapes(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		gotMethod, gotPath, gotQuery, gotBody = r.Method, r.URL.Path, r.URL.RawQuery, string(body)
		if r.URL.Path == "/disclosure-keys" && r.Method == http.MethodGet {
			w.Write([]byte(`{"data":[{"id":"dk_1","name":"Key","fingerprint":"` + strings.Repeat("ab", 32) + `","status":"retiring","retires_at":"2026-10-28T12:00:00Z"}]}`))
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"dsc_1","record":"rec_1","customer":"cus_1","keys":["income"],"status":"pending","disclosure_key":"dk_1","expires_at":"2026-10-24T12:00:00Z","decided_at":null,"created_at":"2026-10-24T11:45:00Z"}`))
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	ctx := context.Background()

	d, err := c.CreateDisclosure(ctx, CreateDisclosureParams{Record: "rec_1", Keys: []string{"income"}, Reason: "Check your income.", Fingerprint: "abcd"})
	if err != nil || d.Status != "pending" || d.Keys[0] != "income" || d.KeyID != "dk_1" || d.DecidedAt != nil {
		t.Fatalf("disclosure: %+v %v", d, err)
	}
	if gotMethod != "POST" || gotPath != "/disclosures" || !strings.Contains(gotBody, `"disclosure_key_fingerprint":"abcd"`) || strings.Contains(gotBody, "expires_in") {
		t.Errorf("unexpected request: %s %s %s", gotMethod, gotPath, gotBody)
	}
	keys, err := c.ListDisclosureKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].RetiresAt == nil || keys[0].Status != "retiring" {
		t.Errorf("keys: %+v %v", keys, err)
	}
	if _, err := c.ListDisclosures(ctx, ListDisclosuresParams{Status: "pending", Limit: 5, StartingAfter: "dsc_0"}); err != nil || gotQuery != "limit=5&starting_after=dsc_0&status=pending" {
		t.Errorf("unexpected query: %s %v", gotQuery, err)
	}
}

func TestRecordMethodsSendAndReadTheRightShapes(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		if r.URL.Path == "/records" {
			w.Write([]byte(`{"data":[{"token":"rec_1","customer":"cus_1","version":2,"keys":[{"name":"income","type":"number","version":2,"updated_at":"2026-10-27T10:00:00Z"}],"created_at":"2026-10-27T09:00:00Z","updated_at":"2026-10-27T10:00:00Z"}],"has_more":true}`))
			return
		}
		w.Write([]byte(`{"token":"rec_1","customer":"cus_1","version":2,"keys":[],"created_at":"2026-10-27T09:00:00Z","updated_at":"2026-10-27T10:00:00Z"}`))
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	page, err := c.ListRecords(context.Background(), ListRecordsParams{Customer: "cus_1", Limit: 5, StartingAfter: "rec_0"})
	if err != nil || !page.HasMore || len(page.Data) != 1 || page.Data[0].Keys[0].Name != "income" || page.Data[0].Keys[0].Version != 2 {
		t.Fatalf("list: %+v %v", page, err)
	}
	if gotPath != "/records" || gotQuery != "customer=cus_1&limit=5&starting_after=rec_0" {
		t.Errorf("unexpected request: %s?%s", gotPath, gotQuery)
	}
	one, err := c.GetRecord(context.Background(), "rec_1")
	if err != nil || one.Token != "rec_1" || gotPath != "/records/rec_1" {
		t.Errorf("get: %+v %v %s", one, err, gotPath)
	}
	body := ""
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(raw)
		body = string(raw)
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"ses_1","customer":"cus_1","purpose":"view","status":"created","livemode":false,"return_url":"https://a.example/x","state":"s","expires_at":"2026-10-27T12:00:00Z","created_at":"2026-10-27T11:45:00Z","record":"rec_1","url":"https://vault.example/b/org_x/view#st=tok"}`))
	}))
	defer srv2.Close()
	c2, _ := New("k", WithBaseURL(srv2.URL))
	session, err := c2.CreateSession(context.Background(), CreateSessionParams{Customer: "cus_1", Purpose: "view", ReturnURL: "https://a.example/x", State: "s", Record: "rec_1", Keys: []Key{{Name: "note", MaxSize: 2048}}})
	if err != nil || session.Record != "rec_1" {
		t.Fatalf("session: %+v %v", session, err)
	}
	if !strings.Contains(body, `"record":"rec_1"`) || !strings.Contains(body, `"max_size":2048`) {
		t.Errorf("the record and the key's size limit must be sent: %s", body)
	}
}

func TestEnvelopeAndAckSendAndReadTheRightShapes(t *testing.T) {
	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		if strings.HasSuffix(r.URL.Path, "/envelope") {
			w.Write([]byte(`{"v":1,"suite":"cdv1-x25519-hkdf256-aes256gcm","request_id":"dsc_1"}`))
			return
		}
		w.Write([]byte(`{"id":"dsc_1","status":"approved","envelope_ready":false,"acked_at":"2026-10-27T10:00:00Z"}`))
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	raw, err := c.GetDisclosureEnvelope(context.Background(), "dsc_1")
	if err != nil || gotMethod != "GET" || gotPath != "/disclosures/dsc_1/envelope" || !strings.Contains(string(raw), `"request_id":"dsc_1"`) {
		t.Errorf("envelope: %s %v %s %s", raw, err, gotMethod, gotPath)
	}
	d, err := c.AckDisclosure(context.Background(), "dsc_1")
	if err != nil || gotMethod != "POST" || gotPath != "/disclosures/dsc_1/ack" || d.AckedAt == nil || d.EnvelopeReady {
		t.Errorf("ack: %+v %v %s %s", d, err, gotMethod, gotPath)
	}
}

func TestApproveURLAddsTheFingerprintToTheFragmentOnly(t *testing.T) {
	fp := strings.Repeat("AB", 32)
	got, err := ApproveURL("https://vault.thecustodian.io/b/org_x/approve#st=cdvs_live_org_x_tok", fp)
	if err != nil || got != "https://vault.thecustodian.io/b/org_x/approve#st=cdvs_live_org_x_tok&fp="+strings.ToLower(fp) {
		t.Errorf("link: %q %v", got, err)
	}
	for name, args := range map[string][2]string{
		"a short fingerprint":      {"https://vault.example/b/o/approve#st=t", "abcd"},
		"a fingerprint with a g":   {"https://vault.example/b/o/approve#st=t", strings.Repeat("g", 64)},
		"a link with no fragment":  {"https://vault.example/b/o/approve", strings.Repeat("a", 64)},
		"a link that is not https": {"http://vault.example/b/o/approve#st=t", strings.Repeat("a", 64)},
	} {
		if _, err := ApproveURL(args[0], args[1]); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestCreateCustomerNamedSendsTheNameThatIsOffered(t *testing.T) {
	var body map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"cus_1","external_ref":"ref","first_name":"Amina","last_name":"Okafor","name_confirmed":false}`))
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	got, err := c.CreateCustomerNamed(context.Background(), "ref", "Amina", "Okafor")
	if err != nil || got.FirstName != "Amina" || got.LastName != "Okafor" || got.NameConfirmed {
		t.Fatalf("customer: %+v %v", got, err)
	}
	if body["external_ref"] != "ref" || body["first_name"] != "Amina" || body["last_name"] != "Okafor" {
		t.Errorf("body: %v", body)
	}
}

func TestAuditEventReadsEveryFieldOfTheSpec(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"id":7,"type":"business.suspended","occurred_at":"2026-10-29T10:00:00Z","staff":true},{"id":8,"type":"api_key.created","occurred_at":"2026-10-29T11:00:00Z","user":"usr_1","user_email":"a@example.com","api_key_label":"cdv_test_Qa7x…m2Lp","livemode":false,"api_key":"key_1","payload":{"k":"v"}}],"total":2}`))
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	events, err := c.ListAuditEvents(context.Background(), 5, 0)
	if err != nil || len(events) != 2 {
		t.Fatalf("events %v, err %v", events, err)
	}
	if !events[0].Staff || events[0].User != "" || events[0].UserEmail != "" || events[0].Livemode != nil {
		t.Fatalf("staff event read wrong: %+v", events[0])
	}
	e := events[1]
	if e.Staff || e.UserEmail != "a@example.com" || e.APIKeyLabel != "cdv_test_Qa7x…m2Lp" || e.Livemode == nil || *e.Livemode || e.APIKey != "key_1" {
		t.Fatalf("api event read wrong: %+v", e)
	}
}

func TestDownloadDisclosedFileStreamsTheBodyAndSendsTheRange(t *testing.T) {
	var gotPath, gotRange, gotAuth, gotIdem string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotRange, gotAuth, gotIdem = r.URL.EscapedPath(), r.Header.Get("Range"), r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key")
		if gotRange != "" {
			w.WriteHeader(http.StatusPartialContent)
		}
		// A slow body: the client's own timeout limits the wait for the answer, not the read.
		w.Write([]byte("abc"))
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("def"))
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL), WithHTTPClient(&http.Client{Timeout: 100 * time.Millisecond}))
	ctx := context.Background()

	body, err := c.DownloadDisclosedFile(ctx, "dsc_1", "id/doc", DownloadFileParams{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(body)
	body.Close()
	if err != nil || string(got) != "abcdef" {
		t.Fatalf("%q, %v", got, err)
	}
	if gotPath != "/disclosures/dsc_1/files/id%2Fdoc" || gotRange != "" || gotAuth != "Bearer k" || gotIdem != "" {
		t.Errorf("path %s, range %q, auth %q, idempotency %q", gotPath, gotRange, gotAuth, gotIdem)
	}

	for want, r := range map[string]ByteRange{"bytes=10-": {Start: 10, End: -1}, "bytes=0-1048575": {Start: 0, End: 1048575}} {
		body, err := c.DownloadDisclosedFile(ctx, "dsc_1", "passport", DownloadFileParams{Range: &r})
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, body)
		body.Close()
		if gotRange != want {
			t.Errorf("range %q, want %q", gotRange, want)
		}
	}
	if _, err := c.DownloadDisclosedFile(ctx, "dsc_1", "passport", DownloadFileParams{Range: &ByteRange{Start: 5, End: 2}}); err == nil {
		t.Error("a range that ends before it starts was sent")
	}
}

func TestDownloadDisclosedFileErrors(t *testing.T) {
	status, body := 0, ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer server.Close()
	c, _ := New("k", WithBaseURL(server.URL))
	ctx := context.Background()

	status, body = http.StatusGone, `{"error":{"type":"invalid_request_error","code":"file_replaced","message":"replaced"}}`
	_, err := c.DownloadDisclosedFile(ctx, "dsc_1", "passport", DownloadFileParams{})
	var apiErr *APIError
	if !errors.Is(err, ErrFileReplaced) || !errors.As(err, &apiErr) || apiErr.Status != http.StatusGone {
		t.Errorf("410 file_replaced: %v", err)
	}
	status, body = http.StatusNotFound, `{"error":{"type":"invalid_request_error","code":"file_not_found","message":"no"}}`
	if _, err := c.DownloadDisclosedFile(ctx, "dsc_1", "passport", DownloadFileParams{}); errors.Is(err, ErrFileReplaced) || !errors.As(err, &apiErr) || apiErr.Code != "file_not_found" {
		t.Errorf("404: %v", err)
	}
	// A server that ignores the range would hand back the whole file where a part was expected.
	status, body = http.StatusOK, "whole file"
	if _, err := c.DownloadDisclosedFile(ctx, "dsc_1", "passport", DownloadFileParams{Range: &ByteRange{Start: 10, End: -1}}); err == nil {
		t.Error("a 200 answer to a range request was accepted")
	}
}
