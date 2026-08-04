package handler_test

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calnode/calnode/internal/calendar"
	"github.com/calnode/calnode/internal/db"
	"github.com/calnode/calnode/internal/gcal"
	"github.com/calnode/calnode/internal/handler"
)

func newManagedCalendarHandler(t *testing.T) (*handler.Handler, *sql.DB, string, string) {
	t.Helper()
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"managed-access-token","expires_in":3600,"token_type":"Bearer"}`))
		case "/tokeninfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"aud":"google-client-id","scope":"` + gcal.CalendarScope + `"}`))
		case "/calendar/v3/calendars/primary":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cal@example.com"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(google.Close)

	database, err := db.Open("sqlite://:memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	h := handler.New(database, slog.Default())
	gc, err := gcal.New(
		database,
		"google-client-id",
		"google-secret",
		"http://localhost:3000/v1/calendar/callback",
		testGCalKeyHex,
		gcal.WithManagedValidationEndpoints(google.URL+"/token", google.URL+"/tokeninfo", google.URL+"/calendar/v3"),
	)
	if err != nil {
		t.Fatalf("gcal.New: %v", err)
	}
	svc := calendar.NewService(database)
	svc.Register(gc)
	h.SetCalendar(svc)
	h.SetBonnieManagedMode(true)

	body := `{"name":"Cal User","email":"cal@example.com","timezone":"UTC"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Setup(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup: got %d — %s", rec.Code, rec.Body.String())
	}
	var setup struct {
		APIKey string `json:"api_key"`
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &setup); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	return h, database, setup.APIKey, setup.UserID
}

const managedCredentialJSON = `{
	"access_token":"managed-access-token",
	"refresh_token":"managed-refresh-token",
	"expires_at":"2027-01-02T03:04:05Z",
	"account_email":"cal@example.com",
	"calendar_id":"primary"
}`

func TestInstallManagedGoogleCredential_installsForAPIKeyMemberOnly(t *testing.T) {
	h, database, apiKey, userID := newManagedCalendarHandler(t)
	req := authReq(http.MethodPut, "/v1/calendar/managed/google", managedCredentialJSON, apiKey)
	rec := httptest.NewRecorder()
	h.RequireAuth(h.InstallManagedGoogleCredential)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 — %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "managed-access-token") || strings.Contains(rec.Body.String(), "managed-refresh-token") {
		t.Fatal("response exposed OAuth token material")
	}
	var response struct {
		Connected    bool   `json:"connected"`
		Provider     string `json:"provider"`
		AccountEmail string `json:"account_email"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Connected || response.Provider != "google" || response.AccountEmail != "cal@example.com" {
		t.Fatalf("response = %+v", response)
	}

	var storedUser string
	if err := database.QueryRow(`SELECT user_id FROM calendar_connections WHERE provider = 'google'`).Scan(&storedUser); err != nil {
		t.Fatalf("read connection: %v", err)
	}
	if storedUser != userID {
		t.Fatalf("stored user = %q; want authenticated user %q", storedUser, userID)
	}
}

func TestInstallManagedGoogleCredential_rejectsBrowserSession(t *testing.T) {
	h, database, _, userID := newManagedCalendarHandler(t)
	if _, err := database.Exec(`INSERT INTO sessions (id,user_id,expires_at) VALUES ('browser-session',?,'2099-01-01T00:00:00Z')`, userID); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/v1/calendar/managed/google", strings.NewReader(managedCredentialJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "calnode_session", Value: "browser-session"})
	rec := httptest.NewRecorder()
	h.RequireAuth(h.InstallManagedGoogleCredential)(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403 — %s", rec.Code, rec.Body.String())
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM calendar_connections`).Scan(&count); err != nil {
		t.Fatalf("count connections: %v", err)
	}
	if count != 0 {
		t.Fatalf("browser session persisted %d connections; want 0", count)
	}
}

func TestRevokeManagedGoogleCredential_removesAuthenticatedMembersConnection(t *testing.T) {
	h, database, apiKey, _ := newManagedCalendarHandler(t)
	installReq := authReq(http.MethodPut, "/v1/calendar/managed/google", managedCredentialJSON, apiKey)
	h.RequireAuth(h.InstallManagedGoogleCredential)(httptest.NewRecorder(), installReq)

	revokeReq := authReq(http.MethodDelete, "/v1/calendar/managed/google", "", apiKey)
	revokeRec := httptest.NewRecorder()
	h.RequireAuth(h.RevokeManagedGoogleCredential)(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204 — %s", revokeRec.Code, revokeRec.Body.String())
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM calendar_connections`).Scan(&count); err != nil {
		t.Fatalf("count connections: %v", err)
	}
	if count != 0 {
		t.Fatalf("remaining connections = %d; want 0", count)
	}
}

func TestConnectCalendar_bonnieManagedModeBlocksSecondConsent(t *testing.T) {
	h, _, apiKey, _ := newManagedCalendarHandler(t)
	req := authReq(http.MethodGet, "/v1/calendar/connect", "", apiKey)
	rec := httptest.NewRecorder()
	h.RequireAuth(h.ConnectCalendar)(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d; want 409 — %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "managed_by_bonnie") {
		t.Fatalf("body = %s; want managed_by_bonnie", rec.Body.String())
	}
}

func TestCalendarStatus_bonnieManagedModeIsExplicit(t *testing.T) {
	h, _, apiKey, _ := newManagedCalendarHandler(t)
	req := authReq(http.MethodGet, "/v1/calendar/status", "", apiKey)
	rec := httptest.NewRecorder()
	h.RequireAuth(h.CalendarStatus)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["managed_by_bonnie"] != true {
		t.Fatalf("managed_by_bonnie = %v; want true", response["managed_by_bonnie"])
	}
}

func TestCalendarStatus_bonnieManagedModeIsExplicitWithoutProvider(t *testing.T) {
	_, database, _, _ := newManagedCalendarHandler(t)
	h := handler.New(database, slog.Default())
	h.SetBonnieManagedMode(true)
	rec := httptest.NewRecorder()
	h.CalendarStatus(rec, httptest.NewRequest(http.MethodGet, "/v1/calendar/status", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["managed_by_bonnie"] != true || response["configured"] != false {
		t.Fatalf("response = %+v; want managed mode with unavailable provider", response)
	}
}
