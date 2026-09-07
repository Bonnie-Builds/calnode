package handler_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/calnode/calnode/internal/calendar"
	"github.com/calnode/calnode/internal/handler"
	"github.com/calnode/calnode/internal/slots"
)

type calendarWorkspaceProvider struct {
	busy []slots.Interval
	err  error
}

func (p *calendarWorkspaceProvider) Name() string                        { return "google" }
func (p *calendarWorkspaceProvider) InvitesGuests() bool                 { return true }
func (p *calendarWorkspaceProvider) AuthURL(string) string               { return "" }
func (p *calendarWorkspaceProvider) EncryptState(string) (string, error) { return "", nil }
func (p *calendarWorkspaceProvider) DecryptState(string) (string, error) { return "", nil }
func (p *calendarWorkspaceProvider) Exchange(context.Context, string, string, string) error {
	return nil
}
func (p *calendarWorkspaceProvider) Connected(context.Context, string) (bool, error) {
	return true, nil
}
func (p *calendarWorkspaceProvider) Disconnect(context.Context, string) error { return nil }
func (p *calendarWorkspaceProvider) HasDestination(context.Context, string) (bool, error) {
	return p.err == nil, p.err
}
func (p *calendarWorkspaceProvider) ListCalendars(context.Context, string, string) ([]calendar.CalendarInfo, error) {
	return nil, nil
}
func (p *calendarWorkspaceProvider) FreeBusy(context.Context, string, time.Time, time.Time) ([]slots.Interval, error) {
	return p.busy, p.err
}
func (p *calendarWorkspaceProvider) CreateEvent(context.Context, string, calendar.CreateEventParams) (string, string, error) {
	return "", "", nil
}
func (p *calendarWorkspaceProvider) UpdateEvent(context.Context, string, string, time.Time, time.Time) error {
	return nil
}
func (p *calendarWorkspaceProvider) UpdateEventLocation(context.Context, string, string, string) error {
	return nil
}
func (p *calendarWorkspaceProvider) CancelEvent(context.Context, string, string) error { return nil }

type managedCalendarResponse struct {
	SchemaVersion int    `json:"schema_version"`
	RangeStart    string `json:"range_start"`
	RangeEnd      string `json:"range_end"`
	TimeZone      string `json:"time_zone"`
	ProviderState string `json:"provider_state"`
	Bookings      []struct {
		BookingRef     string `json:"booking_ref"`
		Title          string `json:"title"`
		StartsAt       string `json:"starts_at"`
		EndsAt         string `json:"ends_at"`
		TimeZone       string `json:"time_zone"`
		CorrelationRef string `json:"correlation_ref"`
	} `json:"bookings"`
	Busy []struct {
		StartsAt string `json:"starts_at"`
		EndsAt   string `json:"ends_at"`
	} `json:"busy"`
	Page struct {
		Limit      int     `json:"limit"`
		HasMore    bool    `json:"has_more"`
		NextCursor *string `json:"next_cursor"`
	} `json:"page"`
}

func managedCalendarHarness(t *testing.T, provider *calendarWorkspaceProvider) (*handler.Handler, *sql.DB, string) {
	t.Helper()
	h, database := managedSetup(t)
	userID := "managed-calendar-user"
	if _, err := database.Exec(`INSERT INTO users
		(id,email,name,iana_timezone,is_owner,is_admin,is_managed_member,company_ref,managed_subject)
		VALUES (?, 'recruiter@example.com', 'Recruiter User', 'America/New_York', 0, 0, 1, 'company_demo', 'sub_tenant_user_123')`, userID); err != nil {
		t.Fatalf("seed managed member: %v", err)
	}
	service := calendar.NewService(database)
	if provider != nil {
		service.Register(provider)
	}
	h.SetCalendar(service)
	return h, database, userID
}

func readManagedCalendar(t *testing.T, h *handler.Handler, jti string, request map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	request["assertion"] = signAssertion(t, validClaims(jti), "test-key-1")
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal calendar request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/calendar/managed-range", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ManagedCalendarRange(rec, req)
	return rec
}

func calendarRangeRequest() map[string]any {
	return map[string]any{
		"from":      "2027-07-01T00:00:00Z",
		"to":        "2027-07-08T00:00:00Z",
		"time_zone": "Asia/Taipei",
		"limit":     10,
	}
}

func TestManagedCalendarRangeExactMemberPrivacyAndBusySubtraction(t *testing.T) {
	provider := &calendarWorkspaceProvider{busy: []slots.Interval{
		{Start: time.Date(2027, 7, 1, 9, 0, 0, 0, time.UTC), End: time.Date(2027, 7, 1, 9, 30, 0, 0, time.UTC)},
		{Start: time.Date(2027, 7, 1, 10, 0, 0, 0, time.UTC), End: time.Date(2027, 7, 1, 11, 0, 0, 0, time.UTC)},
	}}
	h, database, userID := managedCalendarHarness(t, provider)

	if _, err := database.Exec(`INSERT INTO users (id,email,name,iana_timezone) VALUES ('other','other@example.com','Other','UTC')`); err != nil {
		t.Fatalf("seed other user: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO event_types (id,user_id,slug,name,duration_minutes)
		VALUES ('et-owned',?,'owned','Candidate interview',60),
		       ('et-other','other','other','Private board review',60)`, userID); err != nil {
		t.Fatalf("seed event types: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO bookings
		(id,event_type_id,host_id,start_at,end_at,status,location_value,correlation_ref)
		VALUES ('booking-owned','et-owned',?,'2027-07-01T10:00:00Z','2027-07-01T11:00:00Z','confirmed','https://sensitive.example/join','bnc_owned'),
		       ('booking-other','et-other','other','2027-07-01T12:00:00Z','2027-07-01T13:00:00Z','confirmed','Board room','bnc_other')`, userID); err != nil {
		t.Fatalf("seed bookings: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO booking_attendees (id,booking_id,name,email,iana_timezone,is_organizer)
		VALUES ('att-owned','booking-owned','Sensitive Person','sensitive@example.com','Asia/Taipei',1)`); err != nil {
		t.Fatalf("seed attendee: %v", err)
	}

	rec := readManagedCalendar(t, h, "calendar-privacy-000001", calendarRangeRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("calendar range: %d — %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store, max-age=0" {
		t.Fatalf("Cache-Control = %q", got)
	}
	var response managedCalendarResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.SchemaVersion != 1 || response.ProviderState != "ready" || response.TimeZone != "Asia/Taipei" {
		t.Fatalf("unexpected response metadata: %#v", response)
	}
	if len(response.Bookings) != 1 || response.Bookings[0].BookingRef != "booking-owned" || response.Bookings[0].Title != "Candidate interview" {
		t.Fatalf("bookings = %#v", response.Bookings)
	}
	if response.Bookings[0].CorrelationRef != "bnc_owned" || response.Bookings[0].TimeZone != "Asia/Taipei" {
		t.Fatalf("owned booking metadata = %#v", response.Bookings[0])
	}
	if len(response.Busy) != 1 || response.Busy[0].StartsAt != "2027-07-01T09:00:00Z" || response.Busy[0].EndsAt != "2027-07-01T09:30:00Z" {
		t.Fatalf("busy intervals = %#v", response.Busy)
	}
	body := rec.Body.String()
	for _, secret := range []string{"Sensitive Person", "sensitive@example.com", "sensitive.example", "Private board review", "Board room", "bnc_other"} {
		if strings.Contains(body, secret) {
			t.Fatalf("response leaked %q: %s", secret, body)
		}
	}
}

func TestManagedCalendarRangeRejectsHostileAndUnboundedRequests(t *testing.T) {
	h, _ := managedSetup(t)

	nonMember := readManagedCalendar(t, h, "calendar-hostile-000001", calendarRangeRequest())
	if nonMember.Code != http.StatusForbidden || strings.Contains(nonMember.Body.String(), "bookings") {
		t.Fatalf("non-member response = %d %s", nonMember.Code, nonMember.Body.String())
	}

	h, _, _ = managedCalendarHarness(t, nil)
	overRangeRequest := calendarRangeRequest()
	overRangeRequest["to"] = "2027-08-13T00:00:01Z"
	overRange := readManagedCalendar(t, h, "calendar-hostile-000002", overRangeRequest)
	if overRange.Code != http.StatusUnprocessableEntity || strings.Contains(overRange.Body.String(), "bookings") {
		t.Fatalf("over-range response = %d %s", overRange.Code, overRange.Body.String())
	}
	badZoneRequest := calendarRangeRequest()
	badZoneRequest["time_zone"] = "Not/AZone"
	badZone := readManagedCalendar(t, h, "calendar-hostile-000003", badZoneRequest)
	if badZone.Code != http.StatusUnprocessableEntity || strings.Contains(badZone.Body.String(), "bookings") {
		t.Fatalf("invalid-zone response = %d %s", badZone.Code, badZone.Body.String())
	}
	badPageRequest := calendarRangeRequest()
	badPageRequest["limit"] = 101
	badPage := readManagedCalendar(t, h, "calendar-hostile-000004", badPageRequest)
	if badPage.Code != http.StatusUnprocessableEntity || strings.Contains(badPage.Body.String(), "bookings") {
		t.Fatalf("over-page response = %d %s", badPage.Code, badPage.Body.String())
	}
	extraSelector := calendarRangeRequest()
	extraSelector["company_id"] = "company-b"
	extra := readManagedCalendar(t, h, "calendar-hostile-000005", extraSelector)
	if extra.Code != http.StatusBadRequest || strings.Contains(extra.Body.String(), "bookings") {
		t.Fatalf("caller-selected company response = %d %s", extra.Code, extra.Body.String())
	}
}

func TestManagedCalendarRangePaginatesStablyAndSurfacesProviderFailure(t *testing.T) {
	h, database, userID := managedCalendarHarness(t, &calendarWorkspaceProvider{err: errors.New("provider unavailable")})
	if _, err := database.Exec(`INSERT INTO event_types (id,user_id,slug,name,duration_minutes)
		VALUES ('et',?,'event','Planning',30)`, userID); err != nil {
		t.Fatalf("seed event type: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,email,name,iana_timezone)
		VALUES ('other-host','other-host@example.com','Other host','UTC')`); err != nil {
		t.Fatalf("seed other host: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO bookings (id,event_type_id,host_id,start_at,end_at,status)
		VALUES ('a','et',?,'2027-07-01T10:00:00Z','2027-07-01T10:30:00Z','confirmed'),
		       ('b','et','other-host','2027-07-01T10:00:00Z','2027-07-01T10:30:00Z','confirmed')`, userID); err != nil {
		t.Fatalf("seed bookings: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO booking_hosts (id,booking_id,user_id,is_primary)
		VALUES ('b-member-seat','b',?,0)`, userID); err != nil {
		t.Fatalf("seed member booking seat: %v", err)
	}

	firstRequest := calendarRangeRequest()
	firstRequest["time_zone"] = "UTC"
	firstRequest["limit"] = 1
	first := readManagedCalendar(t, h, "calendar-page-000001", firstRequest)
	if first.Code != http.StatusOK {
		t.Fatalf("first page: %d — %s", first.Code, first.Body.String())
	}
	var firstResponse managedCalendarResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil {
		t.Fatalf("decode first page: %v", err)
	}
	if firstResponse.ProviderState != "retryable_failure" || len(firstResponse.Bookings) != 1 || firstResponse.Bookings[0].BookingRef != "a" || !firstResponse.Page.HasMore || firstResponse.Page.NextCursor == nil {
		t.Fatalf("first page = %#v", firstResponse)
	}
	secondRequest := calendarRangeRequest()
	secondRequest["time_zone"] = "UTC"
	secondRequest["limit"] = 1
	secondRequest["cursor"] = *firstResponse.Page.NextCursor
	second := readManagedCalendar(t, h, "calendar-page-000002", secondRequest)
	if second.Code != http.StatusOK {
		t.Fatalf("second page: %d — %s", second.Code, second.Body.String())
	}
	var secondResponse managedCalendarResponse
	if err := json.Unmarshal(second.Body.Bytes(), &secondResponse); err != nil {
		t.Fatalf("decode second page: %v", err)
	}
	if len(secondResponse.Bookings) != 1 || secondResponse.Bookings[0].BookingRef != "b" || secondResponse.Page.HasMore || secondResponse.Page.NextCursor != nil {
		t.Fatalf("second page = %#v", secondResponse)
	}
}
