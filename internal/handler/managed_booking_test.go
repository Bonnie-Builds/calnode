package handler_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calnode/calnode/internal/calendar"
	"github.com/calnode/calnode/internal/custody"
	"github.com/calnode/calnode/internal/gcal"
	"github.com/calnode/calnode/internal/handler"
)

func managedBookingSetup(t *testing.T) (*bookingHarness, string) {
	t.Helper()
	h, database, key, userID := setupWorkspaceWithDB(t)
	slug, _ := seedEventTypeHTTP(t, h, key)
	if _, err := database.Exec(`UPDATE users SET is_owner = 0, is_admin = 0, is_managed_member = 1 WHERE id = ?`, userID); err != nil {
		t.Fatalf("mark managed member: %v", err)
	}
	h.SetBonnieManagedMode(true)
	return &bookingHarness{handler: h, database: database, apiKey: key, userID: userID}, slug
}

type bookingHarness struct {
	handler  *handler.Handler
	database *sql.DB
	apiKey   string
	userID   string
}

type providerObservationCustodyTransport struct{}

func (providerObservationCustodyTransport) Execute(_ context.Context, request custody.Request) (custody.Outcome, error) {
	if request.Operation != custody.OperationEventGet {
		return custody.Outcome{Kind: custody.OutcomeUnavailable}, nil
	}
	return custody.Outcome{
		Kind: custody.OutcomeAccepted,
		Result: json.RawMessage(`{
			"id":"provider-event-1",
			"hangoutLink":"https://meet.google.com/abc-defg-hij"
		}`),
	}, nil
}

func TestManagedBookingUpsertCreateAndReplay(t *testing.T) {
	harness, slug := managedBookingSetup(t)
	body := fmt.Sprintf(`{
		"event_type_slug":%q,
		"booking_id":null,
		"expected_revision":null,
		"start_at":"2026-06-20T10:00:00Z",
		"end_at":"2026-06-20T10:30:00Z",
		"timezone":"UTC",
		"correlation_ref":"bnc-direct-demo-0001-abcdefghijklmnopqrstuvwxyz",
		"organizer":{"name":"Test Host","email":"host@example.com"},
		"participants":[{"name":"Candidate","email":"candidate@example.com"}]
	}`, slug)

	call := func() *httptest.ResponseRecorder {
		req := authReq(http.MethodPost, "/v1/bookings/managed-upsert", body, harness.apiKey)
		req.Header.Set("Idempotency-Key", "meeting:demo:scheduler:1")
		rec := httptest.NewRecorder()
		harness.handler.RequireAuth(harness.handler.ManagedBookingUpsert)(rec, req)
		return rec
	}

	first := call()
	if first.Code != http.StatusCreated {
		t.Fatalf("create status = %d; want 201 — %s", first.Code, first.Body.String())
	}
	var created struct {
		ID             string `json:"id"`
		EventTypeSlug  string `json:"event_type_slug"`
		UpdatedAt      string `json:"updated_at"`
		CorrelationRef string `json:"correlation_ref"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" || created.EventTypeSlug != slug || created.UpdatedAt == "" || created.CorrelationRef == "" {
		t.Fatalf("incomplete create response: %+v", created)
	}

	replay := call()
	if replay.Code != http.StatusCreated || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replay = %d header=%q body=%s", replay.Code, replay.Header().Get("Idempotency-Replayed"), replay.Body.String())
	}
	if replay.Body.String() != first.Body.String() {
		t.Fatal("replay did not return the stored normalized response")
	}

	var bookingCount, participantCount int
	if err := harness.database.QueryRow(`SELECT COUNT(*) FROM bookings`).Scan(&bookingCount); err != nil {
		t.Fatalf("count bookings: %v", err)
	}
	if err := harness.database.QueryRow(`SELECT COUNT(*) FROM booking_attendees WHERE booking_id = ?`, created.ID).Scan(&participantCount); err != nil {
		t.Fatalf("count participants: %v", err)
	}
	if bookingCount != 1 || participantCount != 2 {
		t.Fatalf("booking rows=%d participant rows=%d; want 1/2", bookingCount, participantCount)
	}
	var organizerEmail, candidateEmail string
	if err := harness.database.QueryRow(`SELECT email FROM booking_attendees WHERE booking_id = ? AND is_organizer = 1`, created.ID).Scan(&organizerEmail); err != nil {
		t.Fatalf("read organizer: %v", err)
	}
	if err := harness.database.QueryRow(`SELECT email FROM booking_attendees WHERE booking_id = ? AND is_organizer = 0`, created.ID).Scan(&candidateEmail); err != nil {
		t.Fatalf("read participant: %v", err)
	}
	if organizerEmail != "host@example.com" || candidateEmail != "candidate@example.com" {
		t.Fatalf("organizer=%q participant=%q", organizerEmail, candidateEmail)
	}
}

func TestManagedBookingProviderObservationUsesCustodyRead(t *testing.T) {
	harness, slug := managedBookingSetup(t)
	createBody := fmt.Sprintf(`{
		"event_type_slug":%q,
		"booking_id":null,
		"expected_revision":null,
		"start_at":"2026-06-20T10:00:00Z",
		"end_at":"2026-06-20T10:30:00Z",
		"timezone":"UTC",
		"correlation_ref":"bnc-provider-observation-abcdefghijklmnopqrstuvwxyz",
		"organizer":{"name":"Host","email":"host@example.com"},
		"participants":[{"name":"Candidate","email":"candidate@example.com"}]
	}`, slug)
	createReq := authReq(http.MethodPost, "/v1/bookings/managed-upsert", createBody, harness.apiKey)
	createReq.Header.Set("Idempotency-Key", "meeting:provider-observation:scheduler:1")
	createRec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.ManagedBookingUpsert)(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; want 201 -- %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("decode create: %v", err)
	}
	if _, err := harness.database.Exec(
		`UPDATE bookings SET external_event_id = ? WHERE id = ?`,
		"provider-event-1",
		created.ID,
	); err != nil {
		t.Fatalf("seed provider event: %v", err)
	}

	gc, err := gcal.New(
		harness.database,
		"google-client-id",
		"google-secret",
		"http://localhost:3000/v1/calendar/callback",
		testGCalKeyHex,
		gcal.WithCustodyTransport(providerObservationCustodyTransport{}, "company-a", "instance-1"),
	)
	if err != nil {
		t.Fatalf("gcal.New: %v", err)
	}
	svc := calendar.NewService(harness.database)
	svc.Register(gc)
	harness.handler.SetCalendar(svc)

	req := authReq(
		http.MethodPost,
		"/v1/bookings/"+created.ID+"/managed-provider-observation",
		`{"observation_ref":"reconcile_1_abcdef"}`,
		harness.apiKey,
	)
	req.SetPathValue("id", created.ID)
	rec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.ManagedBookingProviderObservation)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("observation status = %d; want 200 -- %s", rec.Code, rec.Body.String())
	}
	var response struct {
		BookingID              string  `json:"booking_id"`
		ProviderEventPresent   bool    `json:"provider_event_present"`
		ProviderJoinURLPresent bool    `json:"provider_join_url_present"`
		ProviderJoinURL        *string `json:"provider_join_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode observation: %v", err)
	}
	if response.BookingID != created.ID || !response.ProviderEventPresent || !response.ProviderJoinURLPresent || response.ProviderJoinURL == nil || *response.ProviderJoinURL != "https://meet.google.com/abc-defg-hij" {
		t.Fatalf("observation = %+v; want bounded provider facts", response)
	}
}

func TestManagedBookingUpsertRejectsStaleRevision(t *testing.T) {
	harness, slug := managedBookingSetup(t)
	createBody := fmt.Sprintf(`{"event_type_slug":%q,"booking_id":null,"expected_revision":null,"start_at":"2026-06-20T10:00:00Z","end_at":"2026-06-20T10:30:00Z","timezone":"UTC","correlation_ref":"bnc-direct-demo-0002-abcdefghijklmnopqrstuvwxyz","organizer":{"name":"Test Host","email":"host@example.com"},"participants":[{"name":"Candidate","email":"candidate@example.com"}]}`, slug)
	createReq := authReq(http.MethodPost, "/v1/bookings/managed-upsert", createBody, harness.apiKey)
	createReq.Header.Set("Idempotency-Key", "meeting:demo:scheduler:1")
	createRec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.ManagedBookingUpsert)(createRec, createReq)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	updateBody := fmt.Sprintf(`{"event_type_slug":%q,"booking_id":%q,"expected_revision":"stale-revision","start_at":"2026-06-20T11:00:00Z","end_at":"2026-06-20T11:30:00Z","timezone":"UTC","correlation_ref":"bnc-direct-demo-0002-abcdefghijklmnopqrstuvwxyz","organizer":{"name":"Test Host","email":"host@example.com"},"participants":[{"name":"Candidate","email":"candidate@example.com"}]}`, slug, created.ID)
	req := authReq(http.MethodPost, "/v1/bookings/managed-upsert", updateBody, harness.apiKey)
	req.Header.Set("Idempotency-Key", "meeting:demo:scheduler:2")
	rec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.ManagedBookingUpsert)(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "revision_conflict") {
		t.Fatalf("stale revision response = %d — %s", rec.Code, rec.Body.String())
	}
}

func TestManagedBookingUpsertPersistsRescheduledTimezone(t *testing.T) {
	harness, slug := managedBookingSetup(t)
	createBody := fmt.Sprintf(`{"event_type_slug":%q,"booking_id":null,"expected_revision":null,"start_at":"2026-06-20T10:00:00Z","end_at":"2026-06-20T10:30:00Z","timezone":"UTC","correlation_ref":"bnc-direct-demo-timezone-abcdefghijklmnopqrstuvwxyz","organizer":{"name":"Test Host","email":"host@example.com"},"participants":[{"name":"Candidate","email":"candidate@example.com"}]}`, slug)
	createReq := authReq(http.MethodPost, "/v1/bookings/managed-upsert", createBody, harness.apiKey)
	createReq.Header.Set("Idempotency-Key", "meeting:timezone:scheduler:1")
	createRec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.ManagedBookingUpsert)(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create = %d — %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		ID        string `json:"id"`
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	updateBody := fmt.Sprintf(`{"event_type_slug":%q,"booking_id":%q,"expected_revision":%q,"start_at":"2026-06-21T15:00:00Z","end_at":"2026-06-21T15:30:00Z","timezone":"America/New_York","correlation_ref":"bnc-direct-demo-timezone-abcdefghijklmnopqrstuvwxyz","organizer":{"name":"Test Host","email":"host@example.com"},"participants":[{"name":"Candidate","email":"candidate@example.com"}]}`, slug, created.ID, created.UpdatedAt)
	updateReq := authReq(http.MethodPost, "/v1/bookings/managed-upsert", updateBody, harness.apiKey)
	updateReq.Header.Set("Idempotency-Key", "meeting:timezone:scheduler:2")
	updateRec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.ManagedBookingUpsert)(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update = %d — %s", updateRec.Code, updateRec.Body.String())
	}

	getReq := authReq(http.MethodGet, "/v1/bookings/"+created.ID, "", harness.apiKey)
	getReq.SetPathValue("id", created.ID)
	getRec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.GetBooking)(getRec, getReq)
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), `"timezone":"America/New_York"`) {
		t.Fatalf("authoritative read = %d — %s", getRec.Code, getRec.Body.String())
	}
}

func TestManagedBookingCancelIsRevisionBoundAndReplaySafe(t *testing.T) {
	harness, slug := managedBookingSetup(t)
	createBody := fmt.Sprintf(`{"event_type_slug":%q,"booking_id":null,"expected_revision":null,"start_at":"2026-06-20T10:00:00Z","end_at":"2026-06-20T10:30:00Z","timezone":"UTC","correlation_ref":"bnc-direct-demo-0003-abcdefghijklmnopqrstuvwxyz","organizer":{"name":"Test Host","email":"host@example.com"},"participants":[{"name":"Candidate","email":"candidate@example.com"}]}`, slug)
	createReq := authReq(http.MethodPost, "/v1/bookings/managed-upsert", createBody, harness.apiKey)
	createReq.Header.Set("Idempotency-Key", "meeting:demo:scheduler:1")
	createRec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.ManagedBookingUpsert)(createRec, createReq)
	var created struct {
		ID        string `json:"id"`
		UpdatedAt string `json:"updated_at"`
	}
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)

	body := fmt.Sprintf(`{"expected_revision":%q,"reason":"cancelled by organizer"}`, created.UpdatedAt)
	call := func() *httptest.ResponseRecorder {
		req := authReq(http.MethodPost, "/v1/bookings/"+created.ID+"/managed-cancel", body, harness.apiKey)
		req.SetPathValue("id", created.ID)
		req.Header.Set("Idempotency-Key", "meeting:demo:scheduler:2:cancel")
		rec := httptest.NewRecorder()
		harness.handler.RequireAuth(harness.handler.ManagedBookingCancel)(rec, req)
		return rec
	}
	first := call()
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"status":"cancelled"`) {
		t.Fatalf("cancel = %d — %s", first.Code, first.Body.String())
	}
	replay := call()
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotency-Replayed") != "true" || replay.Body.String() != first.Body.String() {
		t.Fatalf("cancel replay = %d header=%q body=%s", replay.Code, replay.Header().Get("Idempotency-Replayed"), replay.Body.String())
	}
}

func TestManagedBookingLocationRejectsStaleRevision(t *testing.T) {
	harness, slug := managedBookingSetup(t)
	createBody := fmt.Sprintf(`{"event_type_slug":%q,"booking_id":null,"expected_revision":null,"start_at":"2026-06-20T10:00:00Z","end_at":"2026-06-20T10:30:00Z","timezone":"UTC","correlation_ref":"bnc-direct-demo-0004-abcdefghijklmnopqrstuvwxyz","organizer":{"name":"Test Host","email":"host@example.com"},"participants":[{"name":"Candidate","email":"candidate@example.com"}]}`, slug)
	createReq := authReq(http.MethodPost, "/v1/bookings/managed-upsert", createBody, harness.apiKey)
	createReq.Header.Set("Idempotency-Key", "meeting:demo:scheduler:1")
	createRec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.ManagedBookingUpsert)(createRec, createReq)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(createRec.Body.Bytes(), &created)
	body := `{"expected_revision":"stale","correlation_ref":"bnc-direct-demo-0004-abcdefghijklmnopqrstuvwxyz","location_value":"https://app.example.com/meetings/rooms/bonnie-room%3Ameeting-demo"}`
	req := authReq(http.MethodPost, "/v1/bookings/"+created.ID+"/managed-location", body, harness.apiKey)
	req.SetPathValue("id", created.ID)
	req.Header.Set("Idempotency-Key", "meeting:demo:scheduler:1:location")
	rec := httptest.NewRecorder()
	harness.handler.RequireAuth(harness.handler.ManagedBookingLocation)(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "revision_conflict") {
		t.Fatalf("location stale revision = %d — %s", rec.Code, rec.Body.String())
	}
}
