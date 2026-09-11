package handler_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestManagedAvailabilityLaunchExactMemberAndReplay(t *testing.T) {
	h, database, userID := managedCalendarHarness(t, nil)
	assertion := signAssertion(t, validClaims("availability-launch-123456789"), "test-key-1")
	post := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/availability", strings.NewReader(url.Values{"assertion": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ManagedAvailabilityExchange(rec, req)
		return rec
	}
	rec := post(assertion)
	if rec.Code != 303 || rec.Header().Get("Location") != "/admin/availability" {
		t.Fatalf("launch: %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || !cookies[0].HttpOnly {
		t.Fatal("missing bounded session cookie")
	}
	var actual string
	if err := database.QueryRow("SELECT user_id FROM sessions WHERE id=?", cookies[0].Value).Scan(&actual); err != nil || actual != userID {
		t.Fatalf("wrong member: %s %v", actual, err)
	}
	if rec := post(assertion); rec.Code != 401 {
		t.Fatalf("replay accepted: %d", rec.Code)
	}
	claims := validClaims("availability-launch-wrong-company")
	claims["company_ref"] = "other-company"
	if rec := post(signAssertion(t, claims, "test-key-1")); rec.Code != 401 {
		t.Fatalf("wrong company accepted: %d", rec.Code)
	}
}
