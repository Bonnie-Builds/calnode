package handler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/calnode/calnode/internal/calendar"
)

type meetingGuestCalendar struct {
	calendarWorkspaceProvider
	created chan calendar.CreateEventParams
}

func (p *meetingGuestCalendar) CreateEvent(_ context.Context, _ string, params calendar.CreateEventParams) (string, string, error) {
	p.created <- params
	return "event_a", "https://meet.google.com/abc-defg-hij", nil
}

func TestCorrelatedGoogleMeetInvitesConfiguredBonnie(t *testing.T) {
	for _, tc := range []struct {
		name, email, invitee, venue, correlation string
		wantStatus, wantGuests                   int
	}{
		{"google", " BONNIE@bonniebuilds.com ", "founder@example.com", "google_meet", "bnc-meeting-demo-0001-abcdefghijklmnopqrstuvwxyz", 201, 1},
		{"duplicate", "bonnie@bonniebuilds.com", "BONNIE@bonniebuilds.com", "google_meet", "bnc-meeting-demo-0001-abcdefghijklmnopqrstuvwxyz", 201, 0},
		{"room", "", "founder@example.com", "link", "bnc-meeting-demo-0001-abcdefghijklmnopqrstuvwxyz", 201, 0},
		{"uncorrelated", "", "founder@example.com", "google_meet", "", 201, 0},
		{"missing", "", "founder@example.com", "google_meet", "bnc-meeting-demo-0001-abcdefghijklmnopqrstuvwxyz", 503, 0},
		{"malformed", "Bonnie <bonnie@bonniebuilds.com>", "founder@example.com", "google_meet", "bnc-meeting-demo-0001-abcdefghijklmnopqrstuvwxyz", 503, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, database, key, _ := setupWorkspaceWithDB(t)
			slug, eventTypeID := seedEventTypeHTTP(t, h, key)
			if _, err := database.Exec(`UPDATE event_types SET location_type = ? WHERE id = ?`, tc.venue, eventTypeID); err != nil {
				t.Fatal(err)
			}
			h.SetBonnieManagedMode(true)
			h.SetBonnieMeetingBotEmail(tc.email)
			provider := &meetingGuestCalendar{created: make(chan calendar.CreateEventParams, 2)}
			service := calendar.NewService(database)
			service.Register(provider)
			h.SetCalendar(service)
			start := "2026-06-20T10:00:00Z" // bookingNow is pinned to June 1 by TestMain.
			body := fmt.Sprintf(`{"event_type_slug":%q,"start_at":%q,"name":"Founder","email":%q,"timezone":"UTC","correlation_ref":%q}`, slug, start, tc.invitee, tc.correlation)
			req := httptest.NewRequest(http.MethodPost, "/v1/bookings", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "meeting-link-invite-"+tc.name)
			rec := httptest.NewRecorder()
			h.CreateBooking(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			var count int
			if rec.Code != http.StatusCreated {
				if err := database.QueryRow(`SELECT COUNT(*) FROM bookings`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("misconfigured booking was persisted: %d", count)
				}
				return
			}
			var result struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			replayReq := httptest.NewRequest(http.MethodPost, "/v1/bookings", strings.NewReader(body))
			replayReq.Header.Set("Content-Type", "application/json")
			replayReq.Header.Set("Idempotency-Key", "meeting-link-invite-"+tc.name)
			replay := httptest.NewRecorder()
			h.CreateBooking(replay, replayReq)
			if replay.Code != rec.Code || replay.Body.String() != rec.Body.String() {
				t.Fatalf("booking replay changed: %d %s", replay.Code, replay.Body.String())
			}
			if err := database.QueryRow(`SELECT COUNT(*) FROM booking_attendees WHERE booking_id = ? AND is_organizer = 0`, result.ID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != tc.wantGuests {
				t.Fatalf("persisted guests: %d", count)
			}
			select {
			case params := <-provider.created:
				if len(params.Attendees) != tc.wantGuests {
					t.Fatalf("calendar guests: %+v", params.Attendees)
				}
				if tc.wantGuests == 1 && params.Attendees[0].Email != "bonnie@bonniebuilds.com" {
					t.Fatalf("wrong guest: %+v", params.Attendees)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("calendar creation did not run")
			}
		})
	}
}
