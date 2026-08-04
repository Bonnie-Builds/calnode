package gcal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newManagedTestClient(t *testing.T, tokenInfoAudience, tokenInfoScopes, primaryEmail string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "managed-refresh-token" {
				http.Error(w, "invalid refresh token", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"refreshed-access-token","expires_in":3600,"token_type":"Bearer"}`))
		case "/tokeninfo":
			if r.URL.Query().Get("access_token") != "refreshed-access-token" {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"aud":"` + tokenInfoAudience + `","scope":"` + tokenInfoScopes + `"}`))
		case "/calendar/v3/calendars/primary":
			if r.Header.Get("Authorization") != "Bearer refreshed-access-token" {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"` + primaryEmail + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client, err := New(
		newTestDB(t),
		"client-id",
		"client-secret",
		"http://localhost/callback",
		testKeyHex,
		WithManagedValidationEndpoints(server.URL+"/token", server.URL+"/tokeninfo", server.URL+"/calendar/v3"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func managedCredential(accountEmail string) ManagedCredential {
	return ManagedCredential{
		AccessToken:  "managed-access-token",
		RefreshToken: "managed-refresh-token",
		Expiry:       time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
		AccountEmail: accountEmail,
		CalendarID:   "primary",
	}
}

func TestInstallManagedCredential_validatesAndEncrypts(t *testing.T) {
	client := newManagedTestClient(t, "client-id", CalendarScope+" openid", "host@example.com")
	seedUser(t, client.db, "user-1")

	result, err := client.InstallManagedCredential(context.Background(), "user-1", managedCredential("HOST@example.com"))
	if err != nil {
		t.Fatalf("InstallManagedCredential: %v", err)
	}
	if result.AccountEmail != "host@example.com" || result.CalendarID != "primary" {
		t.Fatalf("result = %+v; want normalized account and primary calendar", result)
	}

	var accessEnc, refreshEnc, accountEmail string
	if err := client.db.QueryRowContext(context.Background(), `
		SELECT access_token_enc, refresh_token_enc, account_email
		FROM calendar_connections WHERE user_id = ? AND provider = 'google'`, "user-1").
		Scan(&accessEnc, &refreshEnc, &accountEmail); err != nil {
		t.Fatalf("read stored credential: %v", err)
	}
	if strings.Contains(accessEnc, "managed-access-token") || strings.Contains(refreshEnc, "managed-refresh-token") {
		t.Fatal("credential was stored without encryption")
	}
	access, err := client.decrypt(accessEnc)
	if err != nil || string(access) != "refreshed-access-token" {
		t.Fatalf("decrypt access token = %q, %v", string(access), err)
	}
	refresh, err := client.decrypt(refreshEnc)
	if err != nil || string(refresh) != "managed-refresh-token" {
		t.Fatalf("decrypt refresh token = %q, %v", string(refresh), err)
	}
	if accountEmail != "host@example.com" {
		t.Fatalf("account_email = %q; want host@example.com", accountEmail)
	}
}

func TestInstallManagedCredential_rejectsMissingCalendarScopeWithoutPersistence(t *testing.T) {
	client := newManagedTestClient(t, "client-id", "openid email", "host@example.com")
	seedUser(t, client.db, "user-1")

	_, err := client.InstallManagedCredential(context.Background(), "user-1", managedCredential("host@example.com"))
	if !errors.Is(err, ErrManagedMissingScope) {
		t.Fatalf("error = %v; want ErrManagedMissingScope", err)
	}
	assertNoManagedConnection(t, client, "user-1")
}

func TestInstallManagedCredential_rejectsWrongOAuthClientWithoutPersistence(t *testing.T) {
	client := newManagedTestClient(t, "different-client", CalendarScope, "host@example.com")
	seedUser(t, client.db, "user-1")

	_, err := client.InstallManagedCredential(context.Background(), "user-1", managedCredential("host@example.com"))
	if !errors.Is(err, ErrManagedClientMismatch) {
		t.Fatalf("error = %v; want ErrManagedClientMismatch", err)
	}
	assertNoManagedConnection(t, client, "user-1")
}

func TestInstallManagedCredential_rejectsWrongGoogleAccountWithoutPersistence(t *testing.T) {
	client := newManagedTestClient(t, "client-id", CalendarScope, "actual@example.com")
	seedUser(t, client.db, "user-1")

	_, err := client.InstallManagedCredential(context.Background(), "user-1", managedCredential("expected@example.com"))
	if !errors.Is(err, ErrManagedAccountMismatch) {
		t.Fatalf("error = %v; want ErrManagedAccountMismatch", err)
	}
	assertNoManagedConnection(t, client, "user-1")
}

func TestInstallManagedCredential_requiresOfflineRefreshToken(t *testing.T) {
	client := newManagedTestClient(t, "client-id", CalendarScope, "host@example.com")
	seedUser(t, client.db, "user-1")
	credential := managedCredential("host@example.com")
	credential.RefreshToken = ""

	_, err := client.InstallManagedCredential(context.Background(), "user-1", credential)
	if !errors.Is(err, ErrManagedCredentialInvalid) {
		t.Fatalf("error = %v; want ErrManagedCredentialInvalid", err)
	}
	assertNoManagedConnection(t, client, "user-1")
}

func TestInstallManagedCredential_rejectsUnvalidatedNonPrimaryCalendar(t *testing.T) {
	client := newManagedTestClient(t, "client-id", CalendarScope, "host@example.com")
	seedUser(t, client.db, "user-1")
	credential := managedCredential("host@example.com")
	credential.CalendarID = "another@example.com"

	_, err := client.InstallManagedCredential(context.Background(), "user-1", credential)
	if !errors.Is(err, ErrManagedCredentialInvalid) {
		t.Fatalf("error = %v; want ErrManagedCredentialInvalid", err)
	}
	assertNoManagedConnection(t, client, "user-1")
}

func TestInstallManagedCredential_rejectsUnusableRefreshTokenWithoutPersistence(t *testing.T) {
	client := newManagedTestClient(t, "client-id", CalendarScope, "host@example.com")
	seedUser(t, client.db, "user-1")
	credential := managedCredential("host@example.com")
	credential.RefreshToken = "rejected-refresh-token"

	_, err := client.InstallManagedCredential(context.Background(), "user-1", credential)
	if !errors.Is(err, ErrManagedCredentialInvalid) {
		t.Fatalf("error = %v; want ErrManagedCredentialInvalid", err)
	}
	assertNoManagedConnection(t, client, "user-1")
}

func assertNoManagedConnection(t *testing.T, client *Client, userID string) {
	t.Helper()
	connected, err := client.Connected(context.Background(), userID)
	if err != nil {
		t.Fatalf("Connected: %v", err)
	}
	if connected {
		t.Fatal("credential validation failure persisted a connection")
	}
}
