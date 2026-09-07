package custody

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func validRequest() Request {
	return Request{
		Operation:         OperationEventUpsert,
		CompanyRef:        "company-a",
		InstanceRef:       "instance-1",
		MemberSub:         "member@workspace.example.com",
		StableOperationID: "bk:booking-1:user-1",
		Payload:           map[string]any{"calendarId": "primary", "eventId": "cn-bk-booking-1-user-1"},
	}
}

type recordedCall struct {
	method string
	path   string
	body   string
}

// recordingServer captures every request and replies with scripted responses in order.
func recordingServer(t *testing.T, responses []string) (*httptest.Server, *[]recordedCall) {
	t.Helper()
	var mu sync.Mutex
	calls := &[]recordedCall{}
	idx := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		i := idx
		idx++
		*calls = append(*calls, recordedCall{method: r.Method, path: r.URL.Path, body: string(body)})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		resp := "{}"
		if i < len(responses) {
			resp = responses[i]
		}
		io.WriteString(w, resp) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

// ---------------------------------------------------------------------------
// Idempotency key shape (frozen contract: calnode:{companyRef}:{instanceRef}:{operation}:{stableOperationId})
// ---------------------------------------------------------------------------

func TestIdempotencyKey_exactShape(t *testing.T) {
	got := IdempotencyKey(OperationEventUpsert, "company-a", "instance-1", "bk:b1:u1")
	want := "calnode:company-a:instance-1:calendar.event_upsert:bk:b1:u1"
	if got != want {
		t.Fatalf("IdempotencyKey = %q; want %q", got, want)
	}
}

func TestRequestValidate_rejectsInvalidComponents(t *testing.T) {
	base := validRequest()
	cases := map[string]func(*Request){
		"empty companyRef":         func(r *Request) { r.CompanyRef = "" },
		"companyRef leading colon": func(r *Request) { r.CompanyRef = ":bad" },
		"instanceRef whitespace":   func(r *Request) { r.InstanceRef = "inst ace" },
		"empty stableOperationID":  func(r *Request) { r.StableOperationID = "" },
		"memberSub not an email":   func(r *Request) { r.MemberSub = "not-an-email" },
		"unknown operation":        func(r *Request) { r.Operation = Operation("calendar.slots_compute") },
		"ttl below range":          func(r *Request) { r.TTLMinutes = 0 }, // 0 = omit; use explicit out-of-range instead
	}
	for name, mutate := range cases {
		if name == "ttl below range" {
			continue
		}
		r := base
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: expected local validation failure, got nil", name)
		}
	}
	outOfRange := validRequest()
	outOfRange.TTLMinutes = 61
	if err := outOfRange.Validate(); err == nil {
		t.Error("ttl above 60: expected local validation failure")
	}
	negativeTTL := validRequest()
	negativeTTL.TTLMinutes = -1
	if err := negativeTTL.Validate(); err == nil {
		t.Error("negative ttl: expected local validation failure")
	}
}

func TestRequestValidate_acceptsValidRequest(t *testing.T) {
	if err := validRequest().Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	withTTL := validRequest()
	withTTL.TTLMinutes = 60
	if err := withTTL.Validate(); err != nil {
		t.Fatalf("valid ttl=60 rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Envelope shape: ONLY contract fields cross the boundary.
// ---------------------------------------------------------------------------

func TestExecute_envelopeCarriesOnlyContractFields(t *testing.T) {
	srv, calls := recordingServer(t, []string{`{"outcome":"accepted","result":{"id":"evt-1"}}`})
	c := NewClient(srv.URL)
	if _, err := c.Execute(context.Background(), validRequest()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("got %d calls; want 1", len(*calls))
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte((*calls)[0].body), &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	wantKeys := map[string]bool{
		"schemaVersion":     false,
		"operation":         false,
		"companyRef":        false,
		"instanceRef":       false,
		"memberSub":         false,
		"stableOperationId": false,
		"idempotencyKey":    false,
		"payload":           false,
	}
	for key := range envelope {
		if _, ok := wantKeys[key]; !ok {
			t.Errorf("unexpected envelope field %q (credential/kind material must never cross)", key)
		} else {
			wantKeys[key] = true
		}
	}
	for key, seen := range wantKeys {
		if !seen && key != "schemaVersion" {
			t.Errorf("missing expected contract field %q", key)
		}
	}
	if envelope["idempotencyKey"] != "calnode:company-a:instance-1:calendar.event_upsert:bk:booking-1:user-1" {
		t.Errorf("idempotencyKey = %v; want exact contract shape", envelope["idempotencyKey"])
	}
}

func TestExecute_omitsTTLOverrideWhenUnset(t *testing.T) {
	srv, calls := recordingServer(t, []string{`{"outcome":"accepted","result":{}}`})
	c := NewClient(srv.URL)
	req := validRequest() // TTLMinutes unset
	if _, err := c.Execute(context.Background(), req); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains((*calls)[0].body, "ttlMinutes") {
		t.Error("ttlMinutes must be omitted when the caller does not pin one; Bonbon derives it")
	}
}

func TestExecute_localValidationFailsClosedPreNetwork(t *testing.T) {
	srv, calls := recordingServer(t, nil)
	c := NewClient(srv.URL)
	bad := validRequest()
	bad.CompanyRef = ":leading-colon"
	outcome, err := c.Execute(context.Background(), bad)
	if err != nil {
		t.Fatalf("Execute returned transport error for a locally-invalid envelope: %v", err)
	}
	if outcome.Kind != OutcomeRefused || outcome.RefusalState != StateTransportUnauthorized {
		t.Fatalf("outcome = %+v; want refused/transport_unauthorized (fail-closed safe state)", outcome)
	}
	if len(*calls) != 0 {
		t.Fatalf("locally-invalid envelope reached the network (%d calls); must fail pre-network", len(*calls))
	}
}

// ---------------------------------------------------------------------------
// Typed outcome mapping.
// ---------------------------------------------------------------------------

func TestExecute_mapsAcceptedResult(t *testing.T) {
	srv, _ := recordingServer(t, []string{`{"outcome":"accepted","result":{"id":"evt-1","hangoutLink":"https://meet"}}`})
	c := NewClient(srv.URL)
	outcome, err := c.Execute(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if outcome.Kind != OutcomeAccepted || !strings.Contains(string(outcome.Result), "evt-1") {
		t.Fatalf("outcome = %+v; want accepted carrying result", outcome)
	}
}

func TestExecute_mapsReplayedResult(t *testing.T) {
	srv, _ := recordingServer(t, []string{`{"outcome":"replayed","result":{"id":"evt-1"}}`})
	c := NewClient(srv.URL)
	outcome, err := c.Execute(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if outcome.Kind != OutcomeReplayed {
		t.Fatalf("outcome = %+v; want replayed", outcome)
	}
}

func TestExecute_mapsAmbiguousWithReconciliationDirective(t *testing.T) {
	srv, _ := recordingServer(t, []string{`{"outcome":"ambiguous","reconciliation":"calnode_event_get_read_back","result":null}`})
	c := NewClient(srv.URL)
	outcome, err := c.Execute(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if outcome.Kind != OutcomeAmbiguous {
		t.Fatalf("outcome = %+v; want ambiguous", outcome)
	}
	if outcome.Reconciliation != ReconciliationEventGetReadBack {
		t.Fatalf("reconciliation directive = %q; want %q", outcome.Reconciliation, ReconciliationEventGetReadBack)
	}
}

func TestExecute_mapsRefusedSafeStateVerbatim(t *testing.T) {
	responses := []string{
		`{"outcome":"refused","state":"wrong_member","providerErrorClass":"none"}`,
		`{"outcome":"refused","state":"transport_unauthorized","providerErrorClass":"iam_permission_denied"}`,
		`{"outcome":"refused","state":"missing_scope","providerErrorClass":"insufficient_permissions"}`,
	}
	srv, _ := recordingServer(t, responses)
	c := NewClient(srv.URL)
	for i, wantState := range []SafeState{StateWrongMember, StateTransportUnauthorized, StateMissingScope} {
		outcome, err := c.Execute(context.Background(), validRequest())
		if err != nil {
			t.Fatalf("case %d Execute: %v", i, err)
		}
		if outcome.Kind != OutcomeRefused || outcome.RefusalState != wantState {
			t.Fatalf("case %d outcome = %+v; want refused/%s", i, outcome, wantState)
		}
	}
}

func TestExecute_unknownRefusalStateFailsClosedToUnavailable(t *testing.T) {
	srv, _ := recordingServer(t, []string{`{"outcome":"refused","state":"mystery_state","providerErrorClass":"none"}`})
	c := NewClient(srv.URL)
	outcome, err := c.Execute(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if outcome.Kind != OutcomeUnavailable || outcome.RefusalState != StateProviderUnavailable {
		t.Fatalf("outcome = %+v; want unavailable/provider_unavailable (closed taxonomy; unknown must not flip readiness)", outcome)
	}
}

func TestExecute_serverErrorMapsProviderUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL)
	outcome, err := c.Execute(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if outcome.Kind != OutcomeUnavailable || outcome.RefusalState != StateProviderUnavailable {
		t.Fatalf("outcome = %+v; want unavailable/provider_unavailable on 5xx", outcome)
	}
}

func TestExecute_networkFailureMapsProviderUnavailable(t *testing.T) {
	c := NewClient("http://127.0.0.1:1/nope") // nothing listens there
	outcome, err := c.Execute(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if outcome.Kind != OutcomeUnavailable || outcome.RefusalState != StateProviderUnavailable {
		t.Fatalf("outcome = %+v; want unavailable/provider_unavailable on network fault", outcome)
	}
}

func TestExecute_malformedBodyMapsProviderUnavailable(t *testing.T) {
	srv, _ := recordingServer(t, []string{`not-json-at-all`})
	c := NewClient(srv.URL)
	outcome, err := c.Execute(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if outcome.Kind != OutcomeUnavailable {
		t.Fatalf("outcome = %+v; want unavailable on malformed response", outcome)
	}
}

func TestExecute_sendsCallerHeaderWhenConfigured(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Bonbon-Custody-Caller")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"outcome":"accepted","result":{}}`) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL).WithCallerAuth("deployment-secret-value")
	if _, err := c.Execute(context.Background(), validRequest()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotHeader != "deployment-secret-value" {
		t.Errorf("caller header = %q; want deployment-secret-value", gotHeader)
	}
}

// ---------------------------------------------------------------------------
// Ambiguity protocol: same stable identity, no effect-retrying call.
// ---------------------------------------------------------------------------

func TestReconciliationRetainsStableIdentityForReadBack(t *testing.T) {
	// The read-back GET after an ambiguous upsert must target the SAME stable
	// operation identity (only the operation component differs in the key), so
	// Bonbon-side correlation is preserved and no second upsert can be issued.
	upsertKey := IdempotencyKey(OperationEventUpsert, "c", "i", "bk:b1:u1")
	getKey := IdempotencyKey(OperationEventGet, "c", "i", "bk:b1:u1")
	if upsertKey == getKey {
		t.Fatal("upsert and get keys must differ by operation component")
	}
	if !strings.HasPrefix(getKey, "calnode:c:i:") || !strings.HasSuffix(getKey, ":bk:b1:u1") {
		t.Fatalf("get key %q does not preserve tenant + stable identity", getKey)
	}
}

func TestExecute_contextCancelledReturnsError(t *testing.T) {
	srv, _ := recordingServer(t, []string{`{"outcome":"accepted","result":{}}`})
	c := NewClient(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Execute(ctx, validRequest()); err == nil {
		t.Fatal("expected error on cancelled context")
	}
}
