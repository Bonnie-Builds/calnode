package gcal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calnode/calnode/internal/calendar"
	"github.com/calnode/calnode/internal/custody"
	"github.com/calnode/calnode/internal/slots"
)

// fakeCustodyTransport scripts outcomes per request index and records every
// request so tests can assert envelope shape and call sequences.
type fakeCustodyTransport struct {
	outcomes []custody.Outcome
	errs     []error
	requests []custody.Request
}

func (f *fakeCustodyTransport) Execute(ctx context.Context, req custody.Request) (custody.Outcome, error) {
	i := len(f.requests)
	f.requests = append(f.requests, req)
	if i < len(f.errs) && f.errs[i] != nil {
		return custody.Outcome{}, f.errs[i]
	}
	if i < len(f.outcomes) {
		return f.outcomes[i], nil
	}
	return custody.Outcome{Kind: custody.OutcomeUnavailable, RefusalState: custody.StateProviderUnavailable}, nil
}

func accepted(result string) custody.Outcome {
	return custody.Outcome{Kind: custody.OutcomeAccepted, Result: json.RawMessage(result)}
}

func ambiguousOutcome() custody.Outcome {
	return custody.Outcome{Kind: custody.OutcomeAmbiguous, Reconciliation: custody.ReconciliationEventGetReadBack}
}

func refusedOutcome(state custody.SafeState) custody.Outcome {
	return custody.Outcome{Kind: custody.OutcomeRefused, RefusalState: state, ProviderErrorClass: "none"}
}

func newCustodyTestClient(t *testing.T, tx EffectTransport) *Client {
	t.Helper()
	c := newTestClient(t)
	WithCustodyTransport(tx, "company-a", "instance-1")(c)
	return c
}

// seedDestinationConnection inserts a destination connection row with an
// account email but NO tokens — custody mode never decrypts local material.
func seedDestinationConnection(t *testing.T, c *Client, userID, accountEmail string) {
	t.Helper()
	seedUser(t, c.db, userID)
	_, err := c.db.ExecContext(context.Background(), `
		INSERT INTO calendar_connections
		    (id, user_id, provider, account_email, access_token_enc, refresh_token_enc, calendar_id,
		     check_conflicts, is_destination, expiry_at, created_at)
		VALUES (?, ?, 'google', ?, '', '', 'primary', 1, 1, '', '2026-01-01T00:00:00Z')`,
		"conn-"+userID, userID, accountEmail)
	if err != nil {
		t.Fatalf("seedDestinationConnection(%q): %v", userID, err)
	}
}

func eventResultJSON(id, meetLink string) string {
	conf := ""
	if meetLink != "" {
		b, _ := json.Marshal(struct {
			EntryPoints []struct {
				EntryPointType string `json:"entryPointType"`
				URI            string `json:"uri"`
			} `json:"entryPoints"`
		}{EntryPoints: []struct {
			EntryPointType string `json:"entryPointType"`
			URI            string `json:"uri"`
		}{{EntryPointType: "video", URI: meetLink}}})
		conf = `, "conferenceData": ` + string(b)
	}
	return `{"id": "` + id + `", "hangoutLink": "` + meetLink + `"` + conf + `}`
}

// ---------------------------------------------------------------------------
// Envelope shape over the real integration path.
// ---------------------------------------------------------------------------

func TestCustodyCreateEvent_envelopeCarriesExactContractShape(t *testing.T) {
	tx := &fakeCustodyTransport{outcomes: []custody.Outcome{
		accepted(eventResultJSON("evt-created", "https://meet.example/x")),
	}}
	c := newCustodyTestClient(t, tx)
	seedDestinationConnection(t, c, "user-1", "member@workspace.example.com")

	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	eventID, link, err := c.CreateEvent(context.Background(), "user-1", custodyCreateParams("bk:b1:user-1", start))
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if eventID != "evt-created" || link != "https://meet.example/x" {
		t.Fatalf("got (%q,%q); want mapped provider result", eventID, link)
	}
	if len(tx.requests) != 1 {
		t.Fatalf("got %d custody calls; want exactly 1 upsert", len(tx.requests))
	}
	req := tx.requests[0]
	if req.Operation != custody.OperationEventUpsert {
		t.Errorf("operation = %q; want calendar.event_upsert", req.Operation)
	}
	if req.CompanyRef != "company-a" || req.InstanceRef != "instance-1" {
		t.Errorf("tenant pins = %q/%q; want company-a/instance-1", req.CompanyRef, req.InstanceRef)
	}
	if req.MemberSub != "member@workspace.example.com" {
		t.Errorf("memberSub = %q; want provisioned member from connection row", req.MemberSub)
	}
	wantKey := "calnode:company-a:instance-1:calendar.event_upsert:bk:b1:user-1"
	if req.Key() != wantKey {
		t.Errorf("idempotency key = %q; want %q", req.Key(), wantKey)
	}
	if req.Payload["calendarId"] != "primary" {
		t.Errorf("payload.calendarId = %v; want primary", req.Payload["calendarId"])
	}
	composedID, _ := req.Payload["eventId"].(string)
	if !strings.HasPrefix(composedID, "cn-bk-b1-user") || composedID == "" {
		t.Errorf("payload.eventId = %q; want deterministic fork-composed id", composedID)
	}
	if req.Payload["summary"] != "Intro call" {
		t.Errorf("payload.summary = %v; want the Calnode-composed event body", req.Payload["summary"])
	}
}

func TestCustodyCreateEvent_emptyStableKeyFailsClosedPreNetwork(t *testing.T) {
	tx := &fakeCustodyTransport{}
	c := newCustodyTestClient(t, tx)
	seedDestinationConnection(t, c, "user-1", "member@workspace.example.com")

	p := custodyCreateParams("", time.Now())
	_, _, err := c.CreateEvent(context.Background(), "user-1", p)
	if err == nil {
		t.Fatal("expected fail-closed error when no stable operation identity exists")
	}
	if len(tx.requests) != 0 {
		t.Fatalf("invalid identity reached the network (%d calls)", len(tx.requests))
	}
}

func TestCustodyCreateEvent_noDestinationConnectionReturnsNoConnSemantics(t *testing.T) {
	tx := &fakeCustodyTransport{}
	c := newCustodyTestClient(t, tx)

	eventID, link, err := c.CreateEvent(context.Background(), "nobody", custodyCreateParams("bk:b:x", time.Now()))
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if eventID != "" || link != "" {
		t.Fatalf("got (%q,%q); want no-connection semantics", eventID, link)
	}
	if len(tx.requests) != 0 {
		t.Fatalf("no-connection host produced network calls (%d)", len(tx.requests))
	}
}

// ---------------------------------------------------------------------------
// Ambiguity protocol: same stable identity, read-back convergence, zero duplicates.
// ---------------------------------------------------------------------------

func TestCustodyAmbiguousUpsert_convergesViaEventGetWithoutDuplicateEffect(t *testing.T) {
	// Script: upsert → ambiguous; get → event already exists. A later heal retry
	// of the same logical effect must converge to the SAME event with no new
	// provider effect (Bonbon retains the ambiguous ledger entry).
	tx := &fakeCustodyTransport{outcomes: []custody.Outcome{
		ambiguousOutcome(),
		accepted(eventResultJSON("evt-existing", "")),
		ambiguousOutcome(),
		accepted(eventResultJSON("evt-existing", "")),
	}}
	c := newCustodyTestClient(t, tx)
	seedDestinationConnection(t, c, "user-1", "member@workspace.example.com")

	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	firstID, _, err := c.CreateEvent(context.Background(), "user-1", custodyCreateParams("bk:b1:user-1", start))
	if err != nil {
		t.Fatalf("first CreateEvent: %v", err)
	}
	secondID, _, err := c.CreateEvent(context.Background(), "user-1", custodyCreateParams("bk:b1:user-1", start))
	if err != nil {
		t.Fatalf("retry CreateEvent: %v", err)
	}
	if firstID != "evt-existing" || secondID != "evt-existing" {
		t.Fatalf("converged ids = %q / %q; want both evt-existing", firstID, secondID)
	}
	if len(tx.requests) != 4 {
		t.Fatalf("got %d custody calls; want 2 upserts + 2 read-back gets", len(tx.requests))
	}
	for i, req := range tx.requests {
		wantOp := custody.OperationEventUpsert
		if i%2 == 1 {
			wantOp = custody.OperationEventGet
		}
		if req.Operation != wantOp {
			t.Errorf("call %d operation = %q; want %q", i, req.Operation, wantOp)
		}
		if req.StableOperationID != "bk:b1:user-1" {
			t.Errorf("call %d stableOperationId = %q; want the SAME stable identity across effect + read-back", i, req.StableOperationID)
		}
	}
	// The read-back get must carry the same deterministic eventId the upsert used.
	if got := tx.requests[1].Payload["eventId"]; got != tx.requests[0].Payload["eventId"] {
		t.Errorf("read-back eventId %v != upsert eventId %v", got, tx.requests[1].Payload["eventId"])
	}
}

func TestCustodyAmbiguousCancel_neverReissuesEffectAndPendsOnReadBack(t *testing.T) {
	tx := &fakeCustodyTransport{outcomes: []custody.Outcome{
		ambiguousOutcome(),
		accepted(eventResultJSON("evt-still-there", "")), // read-back: still present
	}}
	c := newCustodyTestClient(t, tx)
	seedDestinationConnection(t, c, "user-1", "member@workspace.example.com")

	err := c.CancelEvent(context.Background(), "user-1", "evt-still-there")
	if !errors.Is(err, ErrCustodyPending) {
		t.Fatalf("err = %v; want ErrCustodyPending (unresolved until Bonbon resolves the retained key)", err)
	}
	for i, req := range tx.requests {
		if i > 0 && req.Operation == custody.OperationEventCancel {
			t.Errorf("call %d re-issued a cancel after ambiguity; only read-back calls may follow", i)
		}
	}
	if len(tx.requests) != 2 {
		t.Fatalf("got %d custody calls; want 1 cancel + 1 get", len(tx.requests))
	}
	wantKey := "calnode:company-a:instance-1:calendar.event_cancel:del:evt-still-there"
	if tx.requests[0].Key() != wantKey {
		t.Errorf("cancel key = %q; want %q", tx.requests[0].Key(), wantKey)
	}
}

func TestCustodyCancel_acceptedCompletes(t *testing.T) {
	tx := &fakeCustodyTransport{outcomes: []custody.Outcome{accepted("{}")}}
	c := newCustodyTestClient(t, tx)
	seedDestinationConnection(t, c, "user-1", "member@workspace.example.com")

	if err := c.CancelEvent(context.Background(), "user-1", "evt-gone"); err != nil {
		t.Fatalf("CancelEvent: %v", err)
	}
	req := tx.requests[0]
	if req.Operation != custody.OperationEventCancel || req.Payload["eventId"] != "evt-gone" {
		t.Fatalf("request = %+v; want cancel for evt-gone", req)
	}
}

func TestCustodyUpdateEvent_readModifyWritePreservesEventBody(t *testing.T) {
	existing := `{"id":"evt-9","summary":"Intro call","description":"Booking ID: b9","location":"Room 5",
		"start":{"dateTime":"2026-09-01T10:00:00Z","timeZone":"UTC"},
		"end":{"dateTime":"2026-09-01T11:00:00Z","timeZone":"UTC"},
		"attendees":[{"email":"member@workspace.example.com"}]}`
	tx := &fakeCustodyTransport{outcomes: []custody.Outcome{
		accepted(existing), // read-back base body
		accepted(existing), // put result
	}}
	c := newCustodyTestClient(t, tx)
	seedDestinationConnection(t, c, "user-1", "member@workspace.example.com")

	start := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 2, 15, 30, 0, 0, time.UTC)
	if err := c.UpdateEvent(context.Background(), "user-1", "evt-9", start, end); err != nil {
		t.Fatalf("UpdateEvent: %v", err)
	}
	if len(tx.requests) != 2 || tx.requests[0].Operation != custody.OperationEventGet || tx.requests[1].Operation != custody.OperationEventUpsert {
		t.Fatalf("calls = %+v; want one get then one put", tx.requests)
	}
	put := tx.requests[1]
	if put.Payload["summary"] != "Intro call" || put.Payload["description"] != "Booking ID: b9" {
		t.Errorf("put payload lost the existing event body: %v", put.Payload)
	}
	startMap, _ := put.Payload["start"].(map[string]any)
	if startMap["dateTime"] != "2026-09-02T15:00:00Z" {
		t.Errorf("put payload start = %v; want moved time", put.Payload["start"])
	}
	wantKey := "calnode:company-a:instance-1:calendar.event_upsert:upd:evt-9"
	if put.Key() != wantKey {
		t.Errorf("update key = %q; want %q", put.Key(), wantKey)
	}
}

func TestCustodyRefusalMapping_matchesSchedulerSemantics(t *testing.T) {
	cases := []struct {
		state    custody.SafeState
		noConn   bool // refused(missing) behaves like direct-mode no-connection
		isReauth bool // revoked/expired surface the reconnect-required remedy
	}{
		{state: custody.StateMissing, noConn: true},
		{state: custody.StateRevoked, isReauth: true},
		{state: custody.StateExpired, isReauth: true},
		{state: custody.StateWrongAccount},
		{state: custody.StateWrongMember},
		{state: custody.StateMissingScope},
		{state: custody.StateWorkspaceRequired},
		{state: custody.StateMemberUnavailable},
		{state: custody.StateTransportUnauthorized},
	}
	for _, tc := range cases {
		tx := &fakeCustodyTransport{outcomes: []custody.Outcome{refusedOutcome(tc.state)}}
		c := newCustodyTestClient(t, tx)
		seedDestinationConnection(t, c, "user-1", "member@workspace.example.com")

		id, _, err := c.CreateEvent(context.Background(), "user-1", custodyCreateParams("bk:b1:user-1", time.Now()))
		switch {
		case tc.noConn:
			if err != nil || id != "" {
				t.Errorf("state %s: got (%q,%v); want no-connection semantics", tc.state, id, err)
			}
		case tc.isReauth:
			if !errors.Is(err, calendar.ErrReauthRequired) {
				t.Errorf("state %s: err = %v; want ErrReauthRequired", tc.state, err)
			}
		default:
			if !errors.Is(err, ErrCustodyAuth) {
				t.Errorf("state %s: err = %v; want typed ErrCustodyAuth", tc.state, err)
			}
		}
	}
}

func TestCustodyTransientOutcome_surfacesPendingNotAuthFailure(t *testing.T) {
	tx := &fakeCustodyTransport{outcomes: []custody.Outcome{
		{Kind: custody.OutcomeUnavailable, RefusalState: custody.StateProviderUnavailable, ProviderErrorClass: "network"},
	}}
	c := newCustodyTestClient(t, tx)
	seedDestinationConnection(t, c, "user-1", "member@workspace.example.com")

	_, _, err := c.CreateEvent(context.Background(), "user-1", custodyCreateParams("bk:b1:user-1", time.Now()))
	if !errors.Is(err, ErrCustodyPending) || errors.Is(err, calendar.ErrReauthRequired) {
		t.Fatalf("err = %v; want transient ErrCustodyPending without readiness/auth semantics", err)
	}
}

// ---------------------------------------------------------------------------
// FreeBusy under custody: batched payload, availability policy untouched.
// ---------------------------------------------------------------------------

func TestCustodyFreeBusy_routesBatchedPayloadAndUnionsIntervals(t *testing.T) {
	result := `{"calendars":{"primary":{"busy":[{"start":"2026-06-15T09:00:00Z","end":"2026-06-15T10:00:00Z"}]}}}`
	tx := &fakeCustodyTransport{outcomes: []custody.Outcome{accepted(result)}}
	c := newCustodyTestClient(t, tx)
	seedDestinationConnection(t, c, "user-1", "member@workspace.example.com")

	from := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	intervals, err := c.FreeBusy(context.Background(), "user-1", from, to)
	if err != nil {
		t.Fatalf("FreeBusy: %v", err)
	}
	if len(intervals) != 1 || intervals[0] != (slots.Interval{Start: from.Add(9 * time.Hour), End: from.Add(10 * time.Hour)}) {
		t.Fatalf("intervals = %+v; want parsed busy block", intervals)
	}
	req := tx.requests[0]
	if req.Operation != custody.OperationFreeBusy || req.MemberSub != "member@workspace.example.com" {
		t.Fatalf("request = %+v; want free_busy for the provisioned member", req)
	}
	itemsJSON, _ := json.Marshal(req.Payload["items"])
	var items []map[string]any
	_ = json.Unmarshal(itemsJSON, &items)
	if len(items) != 1 || items[0]["id"] != "primary" {
		t.Fatalf("items = %v; want the connection's selected calendars", req.Payload["items"])
	}
}

func TestCustodyFreeBusy_skipsRowsWithoutProvisionedMember(t *testing.T) {
	tx := &fakeCustodyTransport{}
	c := newCustodyTestClient(t, tx)
	seedDestinationConnection(t, c, "user-1", "") // legacy row without member email

	from := time.Now()
	intervals, err := c.FreeBusy(context.Background(), "user-1", from, from.Add(time.Hour))
	if err != nil {
		t.Fatalf("FreeBusy: %v", err)
	}
	if len(intervals) != 0 {
		t.Fatalf("intervals = %v; want none (fail-open skip)", intervals)
	}
	if len(tx.requests) != 0 {
		t.Fatalf("rows without a provisioned member reached the boundary (%d calls)", len(tx.requests))
	}
}

// ---------------------------------------------------------------------------
// Kind-blind static proof (SAD-E2E-7 preparation): the fork-side adapter code
// carries no credential material or credential-kind branches.
// ---------------------------------------------------------------------------

func TestCustodyAdapterSourceIsKindBlind(t *testing.T) {
	// Production adapter files only: test files legitimately name credential
	// tokens in order to forbid them.
	paths := []string{
		filepath.Join("..", "custody", "custody.go"),
		"custody.go",
	}
	forbidden := []string{
		"google_dwd_v1", "google_oauth_v1", "refresh_token", "private_key",
		"access_token", "client_secret", "credentialkind", "\"kind\"",
		"id_token", "bearer ", "signjwt",
	}
	var content strings.Builder
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		content.Write(b)
	}
	haystack := strings.ToLower(content.String())
	for _, needle := range forbidden {
		if strings.Contains(haystack, needle) {
			t.Errorf("fork adapter source contains forbidden credential/kind token %q", needle)
		}
	}
}

func custodyCreateParams(stableKey string, start time.Time) calendar.CreateEventParams {
	return calendar.CreateEventParams{
		Summary:            "Intro call",
		Description:        "Booking ID: b1",
		Start:              start,
		End:                start.Add(30 * time.Minute),
		OrganizerName:      "Org",
		OrganizerEmail:     "org@example.com",
		StableOperationKey: stableKey,
	}
}
