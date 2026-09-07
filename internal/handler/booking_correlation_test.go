package handler_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBookingCorrelationRoundTrip verifies the stable reusable-link correlation
// contract: a booking POST carrying a correlation_ref persists it, the booking
// read returns it, and the event type remains reusable (no per-Meeting churn).
func TestBookingCorrelationRoundTrip(t *testing.T) {
	h, database, key, _ := setupWorkspaceWithDB(t)
	slug, _ := seedEventTypeHTTP(t, h, key)
	correlation := "bnc-meeting-demo-0001-abcdefghijklmnopqrstuvwxyz"

	body := fmt.Sprintf(`{
		"event_type_slug": %q,
		"start_at": "2026-06-20T10:00:00Z",
		"name": "Test Attendee",
		"email": "attendee@example.com",
		"timezone": "UTC",
		"correlation_ref": %q
	}`, slug, correlation)
	req := httptest.NewRequest(http.MethodPost, "/v1/bookings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.CreateBooking(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create booking: got %d — %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID             string `json:"id"`
		CorrelationRef string `json:"correlation_ref"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.CorrelationRef != correlation {
		t.Fatalf("create response correlation_ref = %q, want %q", created.CorrelationRef, correlation)
	}

	// The booking row persists the correlation ref.
	var stored string
	if err := database.QueryRow(`SELECT COALESCE(correlation_ref,'') FROM bookings WHERE id = ?`, created.ID).Scan(&stored); err != nil {
		t.Fatalf("query booking: %v", err)
	}
	if stored != correlation {
		t.Fatalf("stored correlation_ref = %q, want %q", stored, correlation)
	}

	// The authenticated booking read returns it.
	getReq := authReq(http.MethodGet, "/v1/bookings/"+created.ID, "", key)
	getReq.SetPathValue("id", created.ID)
	getRec := httptest.NewRecorder()
	h.RequireAuth(h.GetBooking)(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get booking: %d — %s", getRec.Code, getRec.Body.String())
	}
	var read struct {
		CorrelationRef string `json:"correlation_ref"`
	}
	json.Unmarshal(getRec.Body.Bytes(), &read)
	if read.CorrelationRef != correlation {
		t.Fatalf("read correlation_ref = %q, want %q", read.CorrelationRef, correlation)
	}
}

// TestBookingCorrelationAbsentIsInert verifies that an absent or malformed
// correlation ref never fails or corrupts the provider booking.
func TestBookingCorrelationAbsentIsInert(t *testing.T) {
	h, database, key, _ := setupWorkspaceWithDB(t)
	slug, _ := seedEventTypeHTTP(t, h, key)

	// Absent ref.
	body := fmt.Sprintf(`{"event_type_slug":%q,"start_at":"2026-06-20T11:00:00Z","name":"A","email":"a@example.com","timezone":"UTC"}`, slug)
	req := httptest.NewRequest(http.MethodPost, "/v1/bookings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.CreateBooking(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("absent ref booking should succeed, got %d — %s", rec.Code, rec.Body.String())
	}

	// Malformed ref (too short, bad chars) — booking still succeeds, ref dropped.
	badBody := fmt.Sprintf(`{"event_type_slug":%q,"start_at":"2026-06-20T12:00:00Z","name":"B","email":"b@example.com","timezone":"UTC","correlation_ref":"<script>"}`, slug)
	req2 := httptest.NewRequest(http.MethodPost, "/v1/bookings", strings.NewReader(badBody))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	h.CreateBooking(rec2, req2)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("malformed ref booking should succeed, got %d — %s", rec2.Code, rec2.Body.String())
	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM bookings`).Scan(&count); err != nil {
		t.Fatalf("count bookings: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 bookings, got %d", count)
	}
}

// TestBookingCorrelationEventTypeReusable verifies the stable event type stays
// reusable across multiple correlated bookings (no per-Meeting event type).
func TestBookingCorrelationEventTypeReusable(t *testing.T) {
	h, database, key, _ := setupWorkspaceWithDB(t)
	slug, eventTypeID := seedEventTypeHTTP(t, h, key)

	for i, ref := range []string{
		"bnc-meeting-a-0001-abcdefghijklmnopqrstuvwxyz",
		"bnc-meeting-b-0001-abcdefghijklmnopqrstuvwxyz",
		"bnc-meeting-a-0001-abcdefghijklmnopqrstuvwxyz",
	} {
		body := fmt.Sprintf(`{
			"event_type_slug": %q,
			"start_at": "2026-06-21T1%01d:00:00Z",
			"name": "Attendee %d",
			"email": "attendee%d@example.com",
			"timezone": "UTC",
			"correlation_ref": %q
		}`, slug, i, i, i, ref)
		req := httptest.NewRequest(http.MethodPost, "/v1/bookings", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.CreateBooking(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("booking %d: got %d — %s", i, rec.Code, rec.Body.String())
		}
	}

	var eventTypeCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM event_types WHERE id = ?`, eventTypeID).Scan(&eventTypeCount); err != nil {
		t.Fatalf("count event types: %v", err)
	}
	if eventTypeCount != 1 {
		t.Fatalf("stable event type must remain a single row, got %d", eventTypeCount)
	}
	var correlationCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM bookings WHERE correlation_ref IS NOT NULL AND event_type_id = ?`, eventTypeID).Scan(&correlationCount); err != nil {
		t.Fatalf("count correlated bookings: %v", err)
	}
	if correlationCount != 3 {
		t.Fatalf("expected 3 correlated bookings (including replay) on the stable event type, got %d", correlationCount)
	}
}
