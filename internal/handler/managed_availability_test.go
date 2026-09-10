package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/calnode/calnode/internal/handler"
)

type availabilityRule struct {
	DayOfWeek int    `json:"dayOfWeek"`
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`
}
type availabilitySnapshot struct {
	SchemaVersion string             `json:"schemaVersion"`
	TimeZone      string             `json:"timeZone"`
	Rules         []availabilityRule `json:"rules"`
	Revision      string             `json:"revision"`
}
type availabilityUpdate struct {
	TimeZone         string             `json:"timeZone"`
	Rules            []availabilityRule `json:"rules"`
	ExpectedRevision string             `json:"expectedRevision"`
}

func availabilityRequest(t *testing.T, h *handler.Handler, jti string, update *availabilityUpdate) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(struct {
		Assertion string              `json:"assertion"`
		Update    *availabilityUpdate `json:"update,omitempty"`
	}{signAssertion(t, validClaims(jti), "test-key-1"), update})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ManagedAvailability(rec, httptest.NewRequest(http.MethodPost, "/v1/calendar/managed-availability", bytes.NewReader(body)))
	return rec
}
func TestManagedAvailabilityReadSaveConflictAndIsolation(t *testing.T) {
	h, database, userID := managedCalendarHarness(t, nil)
	if _, err := database.Exec(`INSERT INTO users(id,email,name,iana_timezone) VALUES('other','other@example.com','Other','UTC')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO availability_rules(id,user_id,day_of_week,start_time,end_time) VALUES('other-rule','other',1,'08:00','09:00')`); err != nil {
		t.Fatal(err)
	}
	read := availabilityRequest(t, h, "availability-read-123456789", nil)
	if read.Code != 200 {
		t.Fatalf("read: %d %s", read.Code, read.Body.String())
	}
	var initial availabilitySnapshot
	if err := json.Unmarshal(read.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	if len(initial.Rules) != 0 || initial.TimeZone != "America/New_York" || len(initial.Revision) != 64 {
		t.Fatalf("initial: %+v", initial)
	}
	update := &availabilityUpdate{TimeZone: "Asia/Taipei", ExpectedRevision: initial.Revision, Rules: []availabilityRule{{1, "10:00", "12:00"}, {1, "13:00", "16:00"}}}
	saved := availabilityRequest(t, h, "availability-save-123456789", update)
	if saved.Code != 200 {
		t.Fatalf("save: %d %s", saved.Code, saved.Body.String())
	}
	var result availabilitySnapshot
	if err := json.Unmarshal(saved.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.TimeZone != "Asia/Taipei" || len(result.Rules) != 2 || result.Revision == initial.Revision {
		t.Fatalf("result: %+v", result)
	}
	if stale := availabilityRequest(t, h, "availability-stale-123456789", update); stale.Code != 409 {
		t.Fatalf("stale: %d", stale.Code)
	}
	if replay := availabilityRequest(t, h, "availability-save-123456789", nil); replay.Code != 401 {
		t.Fatalf("replay: %d", replay.Code)
	}
	var others int
	if err := database.QueryRow(`SELECT COUNT(*) FROM availability_rules WHERE user_id='other'`).Scan(&others); err != nil || others != 1 {
		t.Fatalf("other rules changed: %d %v", others, err)
	}
	var zone string
	if err := database.QueryRow(`SELECT iana_timezone FROM users WHERE id=?`, userID).Scan(&zone); err != nil || zone != "Asia/Taipei" {
		t.Fatalf("timezone not saved: %s %v", zone, err)
	}
	update.ExpectedRevision = result.Revision
	update.Rules = []availabilityRule{}
	if clear := availabilityRequest(t, h, "availability-clear-123456789", update); clear.Code != 200 {
		t.Fatalf("clear: %d %s", clear.Code, clear.Body.String())
	}
}
func TestManagedAvailabilityRejectsInvalidHoursAndZone(t *testing.T) {
	h, _, _ := managedCalendarHarness(t, nil)
	read := availabilityRequest(t, h, "availability-read-invalid-123456", nil)
	var initial availabilitySnapshot
	if err := json.Unmarshal(read.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	cases := []availabilityUpdate{
		{"Invalid/Zone", []availabilityRule{}, initial.Revision},
		{"UTC", []availabilityRule{{1, "12:00", "10:00"}}, initial.Revision},
		{"UTC", []availabilityRule{{1, "10:00", "12:00"}, {1, "11:00", "13:00"}}, initial.Revision},
		{"UTC", []availabilityRule{{7, "10:00", "12:00"}}, initial.Revision},
	}
	for i, update := range cases {
		rec := availabilityRequest(t, h, fmt.Sprintf("availability-invalid-%016d", i), &update)
		if rec.Code != 422 {
			t.Fatalf("case %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestManagedAvailabilityControlsCandidateSlotsAndPreservesOverrides(t *testing.T) {
	h, database, userID := managedCalendarHarness(t, &calendarWorkspaceProvider{})
	date := time.Now().UTC().AddDate(0, 0, 7)
	day := int(date.Weekday())
	dayText := date.Format("2006-01-02")
	if _, err := database.Exec(`INSERT INTO event_types(id,user_id,slug,name,duration_minutes) VALUES('availability-event',?,'availability-test','Availability test',30)`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO event_type_hosts(id,event_type_id,user_id,role) VALUES('availability-host','availability-event',?,'required')`, userID); err != nil {
		t.Fatal(err)
	}
	getSlots := func() []struct {
		Start string `json:"start"`
		End   string `json:"end"`
	} {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/event-types/availability-test/slots?from="+dayText+"&to="+dayText+"&tz=UTC", nil)
		req.SetPathValue("slug", "availability-test")
		rec := httptest.NewRecorder()
		h.GetSlots(rec, req)
		if rec.Code != 200 {
			t.Fatalf("slots: %d %s", rec.Code, rec.Body.String())
		}
		var result struct {
			Slots []struct {
				Start string `json:"start"`
				End   string `json:"end"`
			} `json:"slots"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Slots
	}
	if initial := getSlots(); len(initial) != 0 {
		t.Fatalf("unsaved hours produced slots: %+v", initial)
	}
	read := availabilityRequest(t, h, "availability-slots-read-123456", nil)
	var initial availabilitySnapshot
	if err := json.Unmarshal(read.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	saved := availabilityRequest(t, h, "availability-slots-save-123456", &availabilityUpdate{"UTC", []availabilityRule{{day, "10:00", "11:00"}}, initial.Revision})
	if saved.Code != 200 {
		t.Fatalf("save: %d %s", saved.Code, saved.Body.String())
	}
	actual := getSlots()
	if len(actual) != 2 || actual[0].Start != dayText+"T10:00:00Z" || actual[1].End != dayText+"T11:00:00Z" {
		t.Fatalf("saved hours not used: %+v", actual)
	}
	if _, err := database.Exec(`INSERT INTO availability_overrides(id,user_id,date,is_available) VALUES('day-off',?,?,0)`, userID, dayText); err != nil {
		t.Fatal(err)
	}
	var current availabilitySnapshot
	if err := json.Unmarshal(saved.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	saved = availabilityRequest(t, h, "availability-slots-save2-123456", &availabilityUpdate{"UTC", []availabilityRule{{day, "10:00", "12:00"}}, current.Revision})
	if saved.Code != 200 {
		t.Fatalf("save2: %d %s", saved.Code, saved.Body.String())
	}
	if blocked := getSlots(); len(blocked) != 0 {
		t.Fatalf("date override removed by edit: %+v", blocked)
	}
}
