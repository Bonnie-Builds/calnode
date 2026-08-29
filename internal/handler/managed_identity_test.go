package handler_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/calnode/calnode/internal/db"
	"github.com/calnode/calnode/internal/handler"
)

var managedTestPub, managedTestPriv, _ = ed25519.GenerateKey(rand.Reader)

func managedTestPublicJWKS(t *testing.T) string {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty": "OKP",
			"crv": "Ed25519",
			"kid": "test-key-1",
			"x":   base64.RawURLEncoding.EncodeToString(managedTestPub),
		}},
	})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return string(doc)
}

// managedSetup creates an in-memory handler with the managed identity contract
// configured (issuer, company, public base URL, inline JWKS, allowed kids,
// operator key).
func managedSetup(t *testing.T) (*handler.Handler, *sql.DB) {
	t.Helper()
	database, err := db.Open("sqlite://:memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	h := handler.New(database, slog.Default())
	h.SetBonnieManagedMode(true)
	h.SetManagedIdentityConfig(handler.ManagedIdentityConfig{
		Issuer:        "https://auth.bonnie.test",
		CompanyRef:    "company_demo",
		JWKS:          managedTestPublicJWKS(t),
		AllowedKids:   []string{"test-key-1"},
		OperatorKey:   "operator-secret-0123456789",
		EntryPath:     "/",
		SessionTTL:    time.Hour,
		PublicBaseURL: "https://scheduler.bonnie.test",
	})
	return h, database
}

// signAssertion builds a compact JWS with the test key and the given claims.
func signAssertion(t *testing.T, claims map[string]any, kid string) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	h := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(managedTestPriv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// validClaims returns the frozen default claims for an assertion.
func validClaims(jti string) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"iss":         "https://auth.bonnie.test",
		"aud":         "https://scheduler.bonnie.test",
		"sub":         "sub_tenant_user_123",
		"company_ref": "company_demo",
		"email":       "recruiter@example.com",
		"name":        "Recruiter User",
		"tz":          "America/New_York",
		"iat":         now.Add(-time.Second).Unix(),
		"exp":         now.Add(55 * time.Second).Unix(),
		"jti":         jti,
	}
}

func TestManagedExchangeHappyPath(t *testing.T) {
	h, database := managedSetup(t)
	body, _ := json.Marshal(map[string]string{"assertion": signAssertion(t, validClaims("jti-happy-000001"), "test-key-1")})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("managed session cookie must be Secure/HttpOnly/SameSite=Lax: %#v", cookies)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("expected redirect to /, got %q", loc)
	}

	// A native session must exist, bounded to <=1h.
	var n int
	var managed int
	var expiresAt string
	if err := database.QueryRow(`SELECT COUNT(*), COALESCE(SUM(managed),0), MAX(expires_at) FROM sessions`).Scan(&n, &managed, &expiresAt); err != nil {
		t.Fatalf("query sessions: %v", err)
	}
	if n != 1 || managed != 1 {
		t.Fatalf("expected one managed session, got n=%d managed=%d", n, managed)
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		t.Fatalf("parse expiry: %v", err)
	}
	if exp.Sub(time.Now()) > time.Hour {
		t.Fatalf("managed session exceeds 1h: %v", exp.Sub(time.Now()))
	}

	// User must be a forced member (not admin/owner).
	var isAdmin, isOwner int
	var companyRef, managedSubject string
	if err := database.QueryRow(`SELECT is_admin, is_owner, company_ref, managed_subject FROM users`).
		Scan(&isAdmin, &isOwner, &companyRef, &managedSubject); err != nil {
		t.Fatalf("query user: %v", err)
	}
	if isAdmin != 0 || isOwner != 0 {
		t.Fatalf("managed member must not be admin/owner, got is_admin=%d is_owner=%d", isAdmin, isOwner)
	}
	if companyRef != "company_demo" || managedSubject != "sub_tenant_user_123" {
		t.Fatalf("member projection wrong: company=%q sub=%q", companyRef, managedSubject)
	}
}

func TestManagedExchangeHTTPLoopbackCookieIsBrowserUsable(t *testing.T) {
	h, _ := managedSetup(t)
	h.SetManagedIdentityConfig(handler.ManagedIdentityConfig{
		Issuer:        "https://auth.bonnie.test",
		CompanyRef:    "company_demo",
		JWKS:          managedTestPublicJWKS(t),
		AllowedKids:   []string{"test-key-1"},
		OperatorKey:   "operator-secret-0123456789",
		EntryPath:     "/",
		SessionTTL:    time.Hour,
		PublicBaseURL: "http://localhost:4222",
	})
	claims := validClaims("jti-loopback-00001")
	claims["aud"] = "http://localhost:4222"
	body, _ := json.Marshal(map[string]string{"assertion": signAssertion(t, claims, "test-key-1")})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "calnode_session_local" || cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("loopback managed cookie must be non-Secure/HttpOnly/SameSite=Lax: %#v", cookies)
	}
}

func TestManagedCalendarExchangeEntrypointsUseFixedPaths(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		handler  func(*handler.Handler, http.ResponseWriter, *http.Request)
		expected string
	}{
		{name: "embed", path: "/v1/auth/managed/exchange/calendar/embed", handler: func(h *handler.Handler, w http.ResponseWriter, r *http.Request) { h.ManagedCalendarEmbedExchange(w, r) }, expected: "/admin/calendar/personal/embed"},
		{name: "full", path: "/v1/auth/managed/exchange/calendar/full", handler: func(h *handler.Handler, w http.ResponseWriter, r *http.Request) { h.ManagedCalendarFullExchange(w, r) }, expected: "/admin/calendar/personal"},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h, _ := managedSetup(t)
			body := url.Values{
				"assertion": {signAssertion(t, validClaims(fmt.Sprintf("jti-calendar-%06d", index)), "test-key-1")},
			}.Encode()
			req := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			test.handler(h, rec, req)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != test.expected {
				t.Fatalf("status=%d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
			}
		})
	}
}

func TestManagedExchangeRejectsNonClosedFormBodies(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
	}{
		{name: "extra field", body: "assertion=x&redirect=%2Fevil", contentType: "application/x-www-form-urlencoded"},
		{name: "duplicate assertion", body: "assertion=x&assertion=y", contentType: "application/x-www-form-urlencoded"},
		{name: "unsupported content type", body: "assertion=x", contentType: "text/plain"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h, _ := managedSetup(t)
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange/calendar/embed", strings.NewReader(test.body))
			req.Header.Set("Content-Type", test.contentType)
			rec := httptest.NewRecorder()
			h.ManagedCalendarEmbedExchange(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestManagedExchangeRejectsReplay(t *testing.T) {
	h, _ := managedSetup(t)
	assertion := signAssertion(t, validClaims("jti-replay-000001"), "test-key-1")

	for i := 0; i < 2; i++ {
		body, _ := json.Marshal(map[string]string{"assertion": assertion})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.ManagedExchange(rec, req)
		if i == 0 {
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("first exchange should succeed, got %d", rec.Code)
			}
		} else {
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("replayed exchange should be 401, got %d", rec.Code)
			}
		}
	}
}

func TestManagedExchangeRejectsBadSignature(t *testing.T) {
	h, database := managedSetup(t)
	// Sign with a different (non-allowlisted) key.
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherPub
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "test-key-1"})
	payload, _ := json.Marshal(validClaims("jti-badsig-000001"))
	hx := base64.RawURLEncoding.EncodeToString(header)
	px := base64.RawURLEncoding.EncodeToString(payload)
	forged := hx + "." + px + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherPriv, []byte(hx+"."+px)))

	body, _ := json.Marshal(map[string]string{"assertion": forged})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged signature should be 401, got %d", rec.Code)
	}
	var users, sessions int
	if err := database.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if users != 0 || sessions != 0 {
		t.Fatalf("no user/session state should be created on reject, got users=%d sessions=%d", users, sessions)
	}
}

func TestManagedExchangeRejectsWrongCompany(t *testing.T) {
	h, _ := managedSetup(t)
	claims := validClaims("jti-company-000001")
	claims["company_ref"] = "company_other"
	body, _ := json.Marshal(map[string]string{"assertion": signAssertion(t, claims, "test-key-1")})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong company should be 401, got %d", rec.Code)
	}
}

func TestManagedExchangeRejectsWrongAudience(t *testing.T) {
	h, _ := managedSetup(t)
	claims := validClaims("jti-aud-000001")
	claims["aud"] = "https://evil.example.com"
	body, _ := json.Marshal(map[string]string{"assertion": signAssertion(t, claims, "test-key-1")})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong audience should be 401, got %d", rec.Code)
	}
}

func TestManagedExchangeRejectsExpired(t *testing.T) {
	h, _ := managedSetup(t)
	claims := validClaims("jti-expired-000001")
	now := time.Now().UTC()
	claims["iat"] = now.Add(-2 * time.Minute).Unix()
	claims["exp"] = now.Add(-time.Minute).Unix()
	body, _ := json.Marshal(map[string]string{"assertion": signAssertion(t, claims, "test-key-1")})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired assertion should be 401, got %d", rec.Code)
	}
}

func TestManagedExchangeRejectsUnallowedKid(t *testing.T) {
	h, _ := managedSetup(t)
	body, _ := json.Marshal(map[string]string{"assertion": signAssertion(t, validClaims("jti-kid-000001"), "other-kid")})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unallowed kid should be 401, got %d", rec.Code)
	}
}

func TestManagedExchangeRejectsAuthorityClaims(t *testing.T) {
	h, database := managedSetup(t)
	claims := validClaims("jti-role-claim-0001")
	claims["role"] = "owner"
	body, _ := json.Marshal(map[string]string{"assertion": signAssertion(t, claims, "test-key-1")})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("assertion with role authority should be 401, got %d", rec.Code)
	}
	var users, sessions int
	_ = database.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users)
	_ = database.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions)
	if users != 0 || sessions != 0 {
		t.Fatalf("authority claim must create no user/session state")
	}
}

func TestManagedExchangeIdentityCollision(t *testing.T) {
	h, database := managedSetup(t)
	// Seed a native user with the same email but no managed subject.
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO users (id, email, name, is_admin) VALUES ('native-user', 'recruiter@example.com', 'Native', 1)`)
	if err != nil {
		t.Fatalf("seed native user: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"assertion": signAssertion(t, validClaims("jti-collide-000001"), "test-key-1")})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("identity collision should be 409, got %d", rec.Code)
	}
}

func TestManagedMemberEnsureArchiveReactivate(t *testing.T) {
	h, database := managedSetup(t)

	// Ensure.
	ensureBody, _ := json.Marshal(map[string]string{
		"sub":            "sub_tenant_bob",
		"email":          "bob@example.com",
		"name":           "Bob",
		"member_api_key": "bob-member-key-0123456789abcdef0123456789abcdef",
	})
	ensureEndpoint := h.RequireManagedOperator(h.ManagedEnsureMember)
	req := httptest.NewRequest(http.MethodPost, "/v1/managed/members", bytes.NewReader(ensureBody))
	req.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	rec := httptest.NewRecorder()
	ensureEndpoint(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ensure should be 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Key must be stored hashed only, never plaintext.
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE name = 'bonnie-managed-member'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("expected one managed member key, got %d err=%v", n, err)
	}
	var keyHash string
	if err := database.QueryRow(`SELECT key_hash FROM api_keys WHERE name = 'bonnie-managed-member'`).Scan(&keyHash); err != nil {
		t.Fatalf("query key hash: %v", err)
	}
	if keyHash == "bob-member-key-0123456789abcdef0123456789abcdef" {
		t.Fatalf("member key must never be stored plaintext")
	}

	// Operator auth is required.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/managed/members", bytes.NewReader(ensureBody))
	rec2 := httptest.NewRecorder()
	ensureEndpoint(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("missing operator key should be 401, got %d", rec2.Code)
	}

	// Idempotent re-ensure.
	req3 := httptest.NewRequest(http.MethodPost, "/v1/managed/members", bytes.NewReader(ensureBody))
	req3.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	rec3 := httptest.NewRecorder()
	ensureEndpoint(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("re-ensure should be idempotent 200, got %d", rec3.Code)
	}

	// A different managed subject in the same company is a valid second member,
	// not an identity collision.
	secondBody, _ := json.Marshal(map[string]string{
		"sub": "sub_tenant_alice", "email": "alice@example.com", "name": "Alice",
		"member_api_key": "alice-member-key-0123456789abcdef0123456789abcdef",
	})
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/managed/members", bytes.NewReader(secondBody))
	secondReq.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	secondRec := httptest.NewRecorder()
	ensureEndpoint(secondRec, secondReq)
	if secondRec.Code != http.StatusOK {
		t.Fatalf("second company member should be 200, got %d body=%s", secondRec.Code, secondRec.Body.String())
	}

	// Archive.
	archiveEndpoint := h.RequireManagedOperator(h.ManagedArchiveMember)
	archReq := httptest.NewRequest(http.MethodPost, "/v1/managed/members/sub_tenant_bob/archive", nil)
	archReq.SetPathValue("sub", "sub_tenant_bob")
	archReq.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	archRec := httptest.NewRecorder()
	archiveEndpoint(archRec, archReq)
	if archRec.Code != http.StatusOK {
		t.Fatalf("archive should be 200, got %d body=%s", archRec.Code, archRec.Body.String())
	}
	var archived any
	if err := database.QueryRow(`SELECT archived_at FROM users WHERE managed_subject = 'sub_tenant_bob'`).Scan(&archived); err != nil {
		t.Fatalf("query archived: %v", err)
	}
	if archived == nil {
		t.Fatalf("member should be archived")
	}
	var keyCount int
	_ = database.QueryRow(`SELECT COUNT(*) FROM api_keys ak JOIN users u ON u.id = ak.user_id WHERE ak.name = 'bonnie-managed-member' AND u.managed_subject = 'sub_tenant_bob'`).Scan(&keyCount)
	if keyCount != 0 {
		t.Fatalf("member key should be revoked on archive, got %d", keyCount)
	}

	// Archive idempotency: archiving again is still 200.
	archReq2 := httptest.NewRequest(http.MethodPost, "/v1/managed/members/sub_tenant_bob/archive", nil)
	archReq2.SetPathValue("sub", "sub_tenant_bob")
	archReq2.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	archRec2 := httptest.NewRecorder()
	archiveEndpoint(archRec2, archReq2)
	if archRec2.Code != http.StatusOK {
		t.Fatalf("re-archive should be idempotent 200, got %d", archRec2.Code)
	}

	// Reactivate.
	reactivateEndpoint := h.RequireManagedOperator(h.ManagedReactivateMember)
	reaReq := httptest.NewRequest(http.MethodPost, "/v1/managed/members/sub_tenant_bob/reactivate", nil)
	reaReq.SetPathValue("sub", "sub_tenant_bob")
	reaReq.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	reaRec := httptest.NewRecorder()
	reactivateEndpoint(reaRec, reaReq)
	if reaRec.Code != http.StatusOK {
		t.Fatalf("reactivate should be 200, got %d", reaRec.Code)
	}
	var archivedNow any
	if err := database.QueryRow(`SELECT archived_at FROM users WHERE managed_subject = 'sub_tenant_bob'`).Scan(&archivedNow); err != nil {
		t.Fatalf("query archived after reactivate: %v", err)
	}
	if archivedNow != nil {
		t.Fatalf("member should be active after reactivate")
	}
}

func TestManagedMemberRequiresOperator(t *testing.T) {
	h, _ := managedSetup(t)
	body, _ := json.Marshal(map[string]string{
		"sub": "sub_x", "email": "x@example.com", "name": "X",
		"member_api_key": "x-member-key-0123456789abcdef0123456789abcdef",
	})
	ensureEndpoint := h.RequireManagedOperator(h.ManagedEnsureMember)
	req := httptest.NewRequest(http.MethodPost, "/v1/managed/members", bytes.NewReader(body))
	req.Header.Set("X-Operator-Key", "wrong-key")
	rec := httptest.NewRecorder()
	ensureEndpoint(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong operator key should be 401, got %d", rec.Code)
	}
}

func TestManagedMemberRebindPreservesProviderConnectionAndRotatesKey(t *testing.T) {
	h, database := managedSetup(t)
	oldKey := "old-member-key-0123456789abcdef0123456789abcdef"
	newKey := "new-member-key-0123456789abcdef0123456789abcdef"
	ensureBody, _ := json.Marshal(map[string]string{
		"sub": "legacy-subject", "email": "legacy@example.com", "name": "Legacy",
		"member_api_key": oldKey,
	})
	ensureReq := httptest.NewRequest(http.MethodPost, "/v1/managed/members", bytes.NewReader(ensureBody))
	ensureReq.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	ensureRec := httptest.NewRecorder()
	h.RequireManagedOperator(h.ManagedEnsureMember)(ensureRec, ensureReq)
	if ensureRec.Code != http.StatusOK {
		t.Fatalf("ensure legacy member: got %d body=%s", ensureRec.Code, ensureRec.Body.String())
	}
	var userID string
	if err := database.QueryRow(`SELECT id FROM users WHERE managed_subject = 'legacy-subject'`).Scan(&userID); err != nil {
		t.Fatalf("load legacy member: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO calendar_connections
		(id, user_id, provider, access_token_enc, calendar_id, is_destination)
		VALUES ('connection-1', ?, 'google', 'encrypted-token', 'primary', 1)`, userID); err != nil {
		t.Fatalf("seed provider connection: %v", err)
	}
	rebindBody, _ := json.Marshal(map[string]string{
		"new_sub": "bonnie:canonical-subject", "member_api_key": newKey,
	})
	rebindReq := httptest.NewRequest(http.MethodPost, "/v1/managed/members/legacy-subject/rebind", bytes.NewReader(rebindBody))
	rebindReq.SetPathValue("sub", "legacy-subject")
	rebindReq.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	rebindRec := httptest.NewRecorder()
	h.RequireManagedOperator(h.ManagedRebindMember)(rebindRec, rebindReq)
	if rebindRec.Code != http.StatusOK {
		t.Fatalf("rebind member: got %d body=%s", rebindRec.Code, rebindRec.Body.String())
	}
	var subject, keyHash string
	var connections int
	if err := database.QueryRow(`SELECT managed_subject FROM users WHERE id = ?`, userID).Scan(&subject); err != nil {
		t.Fatalf("read rebound subject: %v", err)
	}
	if err := database.QueryRow(`SELECT key_hash FROM api_keys WHERE user_id = ? AND name = 'bonnie-managed-member'`, userID).Scan(&keyHash); err != nil {
		t.Fatalf("read rebound key: %v", err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM calendar_connections WHERE user_id = ?`, userID).Scan(&connections); err != nil {
		t.Fatalf("read preserved connection: %v", err)
	}
	if subject != "bonnie:canonical-subject" || keyHash != sha256HexForTest(newKey) || keyHash == sha256HexForTest(oldKey) || connections != 1 {
		t.Fatalf("rebind result mismatch: subject=%q connections=%d", subject, connections)
	}
}

func TestManagedSurfaceDenialMiddleware(t *testing.T) {
	h, database := managedSetup(t)
	// Create a managed member with a session cookie.
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO users (id, email, name, company_ref, managed_subject, is_managed_member)
		 VALUES ('managed-1', 'm@example.com', 'M', 'company_demo', 'sub_managed_1', 1)`)
	if err != nil {
		t.Fatalf("seed managed user: %v", err)
	}
	sessID := "sess-managed-1"
	expiresAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if _, err := database.ExecContext(context.Background(),
		`INSERT INTO sessions (id, user_id, expires_at, managed) VALUES (?, ?, ?, 1)`,
		sessID, "managed-1", expiresAt); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// A denied route (e.g. create API key) returns 404.
	req := httptest.NewRequest(http.MethodPost, "/v1/api-keys", nil)
	req.AddCookie(&http.Cookie{Name: "calnode_session", Value: sessID})
	rec := httptest.NewRecorder()
	h.ManagedDenyMiddleware(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("managed member create API key should be 404, got %d", rec.Code)
	}

	// A personal surface (e.g. event types list) passes through.
	req2 := httptest.NewRequest(http.MethodGet, "/v1/event-types", nil)
	req2.AddCookie(&http.Cookie{Name: "calnode_session", Value: sessID})
	rec2 := httptest.NewRecorder()
	h.ManagedDenyMiddleware(next).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("managed member event-types list should pass through, got %d", rec2.Code)
	}

	// The same managed member must also be denied when authenticating with their
	// member API key rather than a browser cookie.
	rawKey := "managed-policy-key-0123456789abcdef0123456789abcdef"
	sum := sha256.Sum256([]byte(rawKey))
	_, err = database.ExecContext(context.Background(),
		`INSERT INTO api_keys (id, user_id, name, key_hash) VALUES ('managed-key-1', 'managed-1', 'bonnie-managed-member', ?)`,
		hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("seed managed API key: %v", err)
	}
	apiReq := httptest.NewRequest(http.MethodPost, "/v1/api-keys", nil)
	apiReq.Header.Set("X-API-Key", rawKey)
	apiRec := httptest.NewRecorder()
	h.ManagedDenyMiddleware(next).ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusNotFound {
		t.Fatalf("managed API-key caller should be denied create API key, got %d", apiRec.Code)
	}

	webhookReq := httptest.NewRequest(http.MethodPost, "/v1/webhooks", nil)
	webhookReq.Header.Set("X-API-Key", rawKey)
	webhookRec := httptest.NewRecorder()
	h.ManagedDenyMiddleware(next).ServeHTTP(webhookRec, webhookReq)
	if webhookRec.Code != http.StatusNotFound {
		t.Fatalf("managed API-key caller should be denied webhook administration, got %d", webhookRec.Code)
	}

	profileReq := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	profileReq.AddCookie(&http.Cookie{Name: "calnode_session", Value: sessID})
	profileRec := httptest.NewRecorder()
	h.ManagedDenyMiddleware(next).ServeHTTP(profileRec, profileReq)
	if profileRec.Code != http.StatusOK {
		t.Fatalf("managed member personal profile should remain available, got %d", profileRec.Code)
	}
}

func TestManagedRootAvoidsEntryPathLoop(t *testing.T) {
	h, database := managedSetup(t)
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO users (id, email, name, company_ref, managed_subject, is_managed_member)
		 VALUES ('managed-root', 'root@example.com', 'Root', 'company_demo', 'sub_root', 1)`)
	if err != nil {
		t.Fatalf("seed managed root user: %v", err)
	}
	_, err = database.ExecContext(context.Background(),
		`INSERT INTO sessions (id, user_id, expires_at, managed) VALUES ('sess-root', 'managed-root', ?, 1)`,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("seed managed root session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "calnode_session", Value: "sess-root"})
	rec := httptest.NewRecorder()
	h.ManagedRoot(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/" {
		t.Fatalf("managed root should redirect to /admin/ without looping, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestManagedExchangeDisabledWithoutMode(t *testing.T) {
	database, err := db.Open("sqlite://:memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	h := handler.New(database, slog.Default())
	body, _ := json.Marshal(map[string]string{"assertion": "x"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/managed/exchange", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ManagedExchange(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("exchange must 404 when managed mode is off, got %d", rec.Code)
	}
}
