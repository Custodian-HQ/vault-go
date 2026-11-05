package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

type seenRequest struct {
	method, path, query, idempotency string
	body                             []byte
}

// recorder answers every request with the body it is given and keeps the last request, read whole.
func recorder(t *testing.T, status int, answer string) (*Client, func() seenRequest) {
	t.Helper()
	var seen seenRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		seen = seenRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Idempotency-Key"), body}
		w.WriteHeader(status)
		w.Write([]byte(answer))
	}))
	t.Cleanup(server.Close)
	c, err := New("k", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	return c, func() seenRequest { return seen }
}

func sameJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Errorf("the body %q is not JSON: %v", got, err)
		return
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("body %s, want %s", got, want)
	}
}

func TestMethodsSendTheBodiesAndQueriesOfTheSpec(t *testing.T) {
	ctx := context.Background()
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 10, 29, 12, 30, 0, 0, time.FixedZone("x", 3600))
	cases := []struct {
		name                string
		status              int
		answer              string
		call                func(*Client) error
		method, path, query string
		body                string // empty means no body
		wantIdempotencyKey  bool
	}{
		{"ResetCustomer", 201, `{}`, func(c *Client) error {
			_, err := c.ResetCustomer(ctx, "cus_1", "https://a.example/r", "st")
			return err
		}, "POST", "/customers/cus_1/reset", "", `{"return_url":"https://a.example/r","state":"st"}`, true},
		{"SetResetContactText", 200, `{}`, func(c *Client) error {
			_, err := c.SetResetContactText(ctx, "Call us")
			return err
		}, "PUT", "/reset-contact-text", "", `{"text":"Call us"}`, false},
		{"ReplaceTemplate", 200, `{}`, func(c *Client) error {
			_, err := c.ReplaceTemplate(ctx, "kyc", []Key{{Name: "b", Type: "file"}})
			return err
		}, "PUT", "/templates/kyc", "", `{"keys":[{"name":"b","type":"file"}]}`, false},
		{"SetRecoveryPolicy", 200, `{}`, func(c *Client) error {
			_, err := c.SetRecoveryPolicy(ctx, 3)
			return err
		}, "PUT", "/recovery-policy", "", `{"recovery_threshold":3}`, false},
		{"GetUsage with a period", 200, `{}`, func(c *Client) error {
			_, err := c.GetUsage(ctx, from, to)
			return err
		}, "GET", "/usage", "from=2026-10-01T00%3A00%3A00Z&to=2026-10-29T11%3A30%3A00Z", "", false},
		{"GetUsage without a period", 200, `{}`, func(c *Client) error {
			_, err := c.GetUsage(ctx, time.Time{}, time.Time{})
			return err
		}, "GET", "/usage", "", "", false},
		{"ListAuditEvents with every filter", 200, `{"data":[]}`, func(c *Client) error {
			_, err := c.ListAuditEvents(ctx, ListAuditEventsParams{Limit: 5, StartingAfter: 9, Type: "api_key.created", Actor: "member", From: from, To: to, Q: "a@example.com"})
			return err
		}, "GET", "/audit-events", "actor=member&from=2026-10-01T00%3A00%3A00Z&limit=5&q=a%40example.com&starting_after=9&to=2026-10-29T11%3A30%3A00Z&type=api_key.created", "", false},
		{"ListAuditEvents with none", 200, `{"data":[]}`, func(c *Client) error {
			_, err := c.ListAuditEvents(ctx, ListAuditEventsParams{})
			return err
		}, "GET", "/audit-events", "", "", false},
		{"CancelDisclosure", 200, `{}`, func(c *Client) error {
			_, err := c.CancelDisclosure(ctx, "dsc_1")
			return err
		}, "POST", "/disclosures/dsc_1/cancel", "", "", true},
		{"RetryWebhookDelivery", 204, ``, func(c *Client) error {
			return c.RetryWebhookDelivery(ctx, 7)
		}, "POST", "/webhook-deliveries/7/retry", "", "", true},
	}
	for _, tc := range cases {
		c, last := recorder(t, tc.status, tc.answer)
		if err := tc.call(c); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		got := last()
		if got.method != tc.method || got.path != tc.path || got.query != tc.query {
			t.Errorf("%s: sent %s %s?%s, want %s %s?%s", tc.name, got.method, got.path, got.query, tc.method, tc.path, tc.query)
		}
		if tc.body == "" && len(got.body) != 0 {
			t.Errorf("%s: sent a body %q", tc.name, got.body)
		}
		if tc.body != "" {
			sameJSON(t, got.body, tc.body)
		}
		if (len(got.idempotency) == 32) != tc.wantIdempotencyKey {
			t.Errorf("%s: idempotency key %q", tc.name, got.idempotency)
		}
	}
}

func TestTheFieldsAddedBySpecAreRead(t *testing.T) {
	ctx := context.Background()

	c, _ := recorder(t, 200, `{"customers":3,"new_customers_7d":2,"pending_disclosures":4}`)
	usage, err := c.GetUsage(ctx, time.Time{}, time.Time{})
	if err != nil || usage.NewCustomers7d != 2 || usage.PendingDisclosures != 4 {
		t.Errorf("usage: %+v %v", usage, err)
	}

	c, _ = recorder(t, 200, `{"data":[{"id":"we_1","url":"https://a.example/h","secret_last4":"ab12","failing_deliveries":3,"last_delivery_at":"2026-10-29T10:00:00Z"}]}`)
	endpoints, err := c.ListWebhookEndpoints(ctx)
	if err != nil || len(endpoints) != 1 || endpoints[0].SecretLast4 != "ab12" || endpoints[0].FailingDeliveries != 3 || endpoints[0].LastDeliveryAt == nil {
		t.Errorf("endpoints: %+v %v", endpoints, err)
	}

	c, _ = recorder(t, 200, `{"data":[{"id":4,"attempts":2,"max_attempts":8,"next_retry_at":"2026-10-29T10:05:00Z"}]}`)
	deliveries, err := c.ListWebhookDeliveries(ctx, ListDeliveriesParams{})
	if err != nil || len(deliveries) != 1 || deliveries[0].MaxAttempts != 8 || deliveries[0].NextRetryAt == nil {
		t.Errorf("deliveries: %+v %v", deliveries, err)
	}

	c, _ = recorder(t, 201, `{"id":"ses_1","secret_not_replayable":true}`)
	session, err := c.CreateSession(ctx, CreateSessionParams{}, WithIdempotencyKey("again"))
	if err != nil || !session.SecretNotReplayable || session.URL != "" {
		t.Errorf("a replayed session: %+v %v", session, err)
	}
}
