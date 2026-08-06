package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/calnode/calnode/internal/uid"
)

// ManagedIdentityConfig is the frozen Bonnie-managed identity contract.
// See the controlling plan's "Frozen contracts (Phase 0, 2026-08-07)" section.
type ManagedIdentityConfig struct {
	Issuer        string
	CompanyRef    string
	JWKSURL       string
	JWKS          string
	AllowedKids   []string
	OperatorKey   string
	EntryPath     string
	LoginRedirect string
	SessionTTL    time.Duration
	PublicBaseURL string
}

type managedIdentityConfig struct {
	issuer        string
	companyRef    string
	jwksURL       string
	jwksInline    string
	allowedKids   []string
	operatorKey   string
	entryPath     string
	loginRedirect string
	sessionTTL    time.Duration
	publicBaseURL string
}

// managedClaimValues is the validated content of a ManagedCalnodeSessionAssertionV1.
type managedClaimValues struct {
	Sub        string
	Email      string
	Name       string
	CompanyRef string
	IANATZ     string
	JTI        string
}

const (
	managedAssertionMaxBody = 16 << 10
	managedAssertionMaxAge  = 60 * time.Second
	managedSkew             = 30 * time.Second
	maxManagedNameLen       = 256
	maxManagedEmailLen      = 320
	minJTILen               = 16
	maxJTILen               = 128
	managedMemberKeyName    = "bonnie-managed-member"
	maxOperatorBody         = 64 << 10
	maxCorrelationLen       = 64
)

// jwksSet is a parsed JWKS document (public verification keys only).
type jwksSet struct {
	Keys map[string]ed25519.PublicKey // keyed by kid
}

// jsonJWKS mirrors the JSON Web Key Set wire shape for Ed25519 keys.
type jsonJWKS struct {
	Keys []jsonJWK `json:"keys"`
}

type jsonJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

// parseJWKS parses an inline JSON JWKS document. Returns nil on any error.
func parseJWKS(doc string) *jwksSet {
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	var parsed jsonJWKS
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return nil
	}
	set := &jwksSet{Keys: make(map[string]ed25519.PublicKey, len(parsed.Keys))}
	for _, k := range parsed.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		set.Keys[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(set.Keys) == 0 {
		return nil
	}
	return set
}

// kidAllowed reports whether kid is in the configured allowlist.
func (h *Handler) kidAllowed(kid string) bool {
	h.managedMu.RLock()
	allowed := h.managedIdentity.allowedKids
	h.managedMu.RUnlock()
	for _, a := range allowed {
		if a == kid {
			return true
		}
	}
	return false
}

// resolveVerifyKey returns the verification key for kid, refreshing from the
// JWKS URL when configured. The inline JWKS is authoritative when no URL is set.
func (h *Handler) resolveVerifyKey(ctx context.Context, kid string) (ed25519.PublicKey, bool) {
	h.managedMu.RLock()
	cfg := h.managedIdentity
	inline := h.managedJWKS
	h.managedMu.RUnlock()

	if cfg.jwksURL != "" {
		if fetched := fetchJWKS(ctx, cfg.jwksURL); fetched != nil {
			if key, ok := fetched.Keys[kid]; ok {
				return key, true
			}
		}
		// Fall back to the inline document for the overlap window.
	}
	if inline != nil {
		if key, ok := inline.Keys[kid]; ok {
			return key, true
		}
	}
	return nil, false
}

// fetchJWKS fetches and parses a remote JWKS document. Best-effort: returns nil
// on any transport/parse error so verification fails closed.
func fetchJWKS(ctx context.Context, rawURL string) *jwksSet {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil
	}
	return parseJWKS(string(body))
}

// verifyManagedAssertion verifies the compact JWS and validates the frozen
// claims. Returns the validated claim values, or a typed error for diagnostics.
func (h *Handler) verifyManagedAssertion(ctx context.Context, compact string) (*managedClaimValues, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("assertion: not a compact JWS")
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	headerRaw, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, errors.New("assertion: invalid header encoding")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeStrictJSON(headerRaw, &header); err != nil {
		return nil, errors.New("assertion: invalid header")
	}
	if header.Alg != "EdDSA" {
		return nil, errors.New("assertion: unsupported alg")
	}
	if header.Kid == "" {
		return nil, errors.New("assertion: missing kid")
	}
	if !h.kidAllowed(header.Kid) {
		return nil, errors.New("assertion: kid not allowlisted")
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("assertion: invalid signature")
	}
	key, ok := h.resolveVerifyKey(ctx, header.Kid)
	if !ok {
		return nil, errors.New("assertion: verification key unavailable")
	}
	signingInput := headerB64 + "." + payloadB64
	if !ed25519.Verify(key, []byte(signingInput), sig) {
		return nil, errors.New("assertion: signature verification failed")
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New("assertion: invalid payload encoding")
	}
	var claims struct {
		Iss        string `json:"iss"`
		Aud        string `json:"aud"`
		Sub        string `json:"sub"`
		CompanyRef string `json:"company_ref"`
		Email      string `json:"email"`
		Name       string `json:"name"`
		TZ         string `json:"tz"`
		IAT        int64  `json:"iat"`
		Exp        int64  `json:"exp"`
		JTI        string `json:"jti"`
	}
	if err := decodeStrictJSON(payloadRaw, &claims); err != nil {
		return nil, errors.New("assertion: invalid payload")
	}

	h.managedMu.RLock()
	issuer := h.managedIdentity.issuer
	companyRef := h.managedIdentity.companyRef
	publicBaseURL := h.managedIdentity.publicBaseURL
	h.managedMu.RUnlock()

	if claims.Iss == "" || claims.Iss != issuer {
		return nil, errors.New("assertion: issuer mismatch")
	}
	if claims.Aud == "" || claims.Aud != publicBaseURL {
		return nil, errors.New("assertion: audience mismatch")
	}
	if claims.Sub == "" || len(claims.Sub) > 512 {
		return nil, errors.New("assertion: invalid subject")
	}
	if claims.CompanyRef == "" || claims.CompanyRef != companyRef {
		return nil, errors.New("assertion: company mismatch")
	}
	now := time.Now().UTC()
	if claims.IAT <= 0 || claims.Exp <= claims.IAT || claims.Exp-claims.IAT > int64(managedAssertionMaxAge.Seconds()) {
		return nil, errors.New("assertion: invalid time window")
	}
	if time.Unix(claims.Exp, 0).Add(managedSkew).Before(now) {
		return nil, errors.New("assertion: expired")
	}
	if time.Unix(claims.IAT, 0).After(now.Add(managedSkew)) {
		return nil, errors.New("assertion: issued in future")
	}
	if len(claims.JTI) < minJTILen || len(claims.JTI) > maxJTILen {
		return nil, errors.New("assertion: invalid jti")
	}
	for _, c := range claims.JTI {
		if !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
			return nil, errors.New("assertion: invalid jti")
		}
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" || len(email) > maxManagedEmailLen {
		return nil, errors.New("assertion: invalid email")
	}
	parsedEmail, err := mail.ParseAddress(email)
	if err != nil || parsedEmail.Address != email {
		return nil, errors.New("assertion: invalid email")
	}
	name := strings.TrimSpace(claims.Name)
	if name == "" || len(name) > maxManagedNameLen {
		return nil, errors.New("assertion: invalid name")
	}
	tz := strings.TrimSpace(claims.TZ)
	if tz != "" {
		if _, err := time.LoadLocation(tz); err != nil {
			return nil, errors.New("assertion: invalid timezone")
		}
	}

	return &managedClaimValues{
		Sub:        claims.Sub,
		Email:      email,
		Name:       name,
		CompanyRef: claims.CompanyRef,
		IANATZ:     tz,
		JTI:        claims.JTI,
	}, nil
}

// consumeJTI atomically records a one-time assertion ID. Returns false when the
// jti was already consumed (replay).
func (h *Handler) consumeJTI(ctx context.Context, jti string) (bool, error) {
	res, err := h.db.ExecContext(ctx,
		`INSERT INTO managed_assertions (jti, sub) VALUES (?, ?)`,
		jti, "")
	if err != nil {
		if isUniqueViolation(err) {
			return false, nil
		}
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// upsertManagedMember resolves/creates the managed member projection. The user
// is keyed by managed_subject + company_ref; email/name are refreshed. Returns
// the user ID, or an error on identity collision or DB failure.
func (h *Handler) upsertManagedMember(ctx context.Context, v *managedClaimValues) (string, error) {
	var existingID string
	err := h.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE managed_subject = ? AND company_ref = ?`,
		v.Sub, v.CompanyRef).Scan(&existingID)
	if err == nil {
		if _, err := h.db.ExecContext(ctx,
			`UPDATE users SET email = ?, name = ?, iana_timezone = COALESCE(?, iana_timezone),
			   is_admin = 0, is_owner = 0, email_login = 0, archived_at = NULL, is_managed_member = 1
			 WHERE id = ?`,
			v.Email, v.Name, nullIfEmpty(v.IANATZ), existingID); err != nil {
			return "", err
		}
		return existingID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	// New member. Check for identity collision: an existing user with the same
	// email or the same subject mapped under a different company.
	var collisionID string
	_ = h.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE email = ? OR managed_subject = ? LIMIT 1`,
		v.Email, v.Sub).Scan(&collisionID)
	if collisionID != "" {
		return "", errIdentityCollision
	}

	userID := uid.New()
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, iana_timezone, is_admin, is_owner, email_login, company_ref, managed_subject, is_managed_member)
		 VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?, 1)`,
		userID, v.Email, v.Name, defaultTZ(v.IANATZ), v.CompanyRef, v.Sub); err != nil {
		return "", err
	}
	return userID, nil
}

// getManagedMemberBySub returns the managed member's ID for the configured company.
func (h *Handler) getManagedMemberBySub(ctx context.Context, sub string) (string, bool) {
	h.managedMu.RLock()
	companyRef := h.managedIdentity.companyRef
	h.managedMu.RUnlock()
	var id string
	err := h.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE managed_subject = ? AND company_ref = ?`,
		sub, companyRef).Scan(&id)
	if err != nil {
		return "", false
	}
	return id, true
}

// ManagedExchange handles POST /v1/auth/managed/exchange. It validates the
// assertion, consumes its jti once, upserts the forced member, and creates a
// native session bounded to the managed session TTL (<=1h).
func (h *Handler) ManagedExchange(w http.ResponseWriter, r *http.Request) {
	if !h.bonnieManagedMode {
		h.writeCodedError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, managedAssertionMaxBody)
	var req struct {
		Assertion string `json:"assertion"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid exchange request")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid exchange request")
		return
	}
	if req.Assertion == "" {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "assertion required")
		return
	}

	ctx := r.Context()
	claims, err := h.verifyManagedAssertion(ctx, req.Assertion)
	if err != nil {
		h.logger.WarnContext(ctx, "managed exchange rejected", "reason", err.Error())
		h.writeCodedError(w, http.StatusUnauthorized, "managed_assertion_rejected", "assertion rejected")
		return
	}

	consumed, err := h.consumeJTI(ctx, claims.JTI)
	if err != nil {
		h.logger.ErrorContext(ctx, "managed exchange: jti consume failed", "error", err)
		h.writeCodedError(w, http.StatusServiceUnavailable, "exchange_unavailable", "exchange unavailable")
		return
	}
	if !consumed {
		h.logger.WarnContext(ctx, "managed exchange rejected", "reason", "replayed jti")
		h.writeCodedError(w, http.StatusUnauthorized, "managed_assertion_rejected", "assertion rejected")
		return
	}

	userID, err := h.upsertManagedMember(ctx, claims)
	if err != nil {
		h.logger.WarnContext(ctx, "managed exchange member failed", "error", err)
		if errors.Is(err, errIdentityCollision) {
			h.writeCodedError(w, http.StatusConflict, "identity_collision", "identity collision")
			return
		}
		h.writeCodedError(w, http.StatusServiceUnavailable, "exchange_unavailable", "exchange unavailable")
		return
	}

	if err := h.createManagedSession(ctx, w, userID); err != nil {
		h.logger.ErrorContext(ctx, "managed exchange: session failed", "error", err)
		h.writeCodedError(w, http.StatusServiceUnavailable, "exchange_unavailable", "exchange unavailable")
		return
	}

	h.managedMu.RLock()
	entryPath := h.managedIdentity.entryPath
	h.managedMu.RUnlock()
	if entryPath == "" || !isManagedEntryPathSafe(entryPath) {
		entryPath = "/"
	}
	http.Redirect(w, r, entryPath, http.StatusSeeOther)
}

// createManagedSession creates a session bounded to the managed session TTL
// (default 1h, never longer) and sets the native cookie.
func (h *Handler) createManagedSession(ctx context.Context, w http.ResponseWriter, userID string) error {
	h.managedMu.RLock()
	ttl := h.managedIdentity.sessionTTL
	h.managedMu.RUnlock()
	if ttl <= 0 || ttl > time.Hour {
		ttl = time.Hour
	}
	return h.createSessionTTL(ctx, w, userID, ttl, true)
}

// ensureManagedMember is the operator-key path: idempotently upserts the member
// and installs the Bonbon-generated member API key hash.
func (h *Handler) ensureManagedMember(ctx context.Context, sub, email, name, memberAPIKey string) (string, error) {
	h.managedMu.RLock()
	companyRef := h.managedIdentity.companyRef
	h.managedMu.RUnlock()

	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)
	if sub == "" || len(sub) > 512 || email == "" || len(email) > maxManagedEmailLen || name == "" || len(name) > maxManagedNameLen || memberAPIKey == "" {
		return "", errors.New("managed member: missing fields")
	}
	parsedEmail, err := mail.ParseAddress(email)
	if err != nil || parsedEmail.Address != email {
		return "", errors.New("managed member: invalid email")
	}
	if len(memberAPIKey) < 32 {
		return "", errors.New("managed member: member key too short")
	}

	var existingID string
	err = h.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE managed_subject = ? AND company_ref = ?`,
		sub, companyRef).Scan(&existingID)
	if err == nil {
		if _, err := h.db.ExecContext(ctx,
			`UPDATE users SET email = ?, name = ?, is_admin = 0, is_owner = 0, email_login = 0,
			   archived_at = NULL, is_managed_member = 1 WHERE id = ?`,
			email, name, existingID); err != nil {
			return "", err
		}
		if err := upsertManagedMemberKey(ctx, h.db, existingID, memberAPIKey); err != nil {
			return "", err
		}
		return existingID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	var collisionID string
	_ = h.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE email = ? OR managed_subject = ? LIMIT 1`,
		email, sub).Scan(&collisionID)
	if collisionID != "" {
		return "", errIdentityCollision
	}

	userID := uid.New()
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, iana_timezone, is_admin, is_owner, email_login, company_ref, managed_subject, is_managed_member)
		 VALUES (?, ?, ?, 'UTC', 0, 0, 0, ?, ?, 1)`,
		userID, email, name, companyRef, sub); err != nil {
		return "", err
	}
	if err := upsertManagedMemberKey(ctx, h.db, userID, memberAPIKey); err != nil {
		return "", err
	}
	return userID, nil
}

// upsertManagedMemberKey installs the Bonbon-generated member API key for a user.
// Only the SHA-256 hash is stored; the key itself is never persisted.
func upsertManagedMemberKey(ctx context.Context, db *sql.DB, userID, memberAPIKey string) error {
	hash := hashAPIKey(memberAPIKey)
	res, err := db.ExecContext(ctx,
		`UPDATE api_keys SET key_hash = ? WHERE user_id = ? AND name = ?`,
		hash, userID, managedMemberKeyName)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		_, err = db.ExecContext(ctx,
			`INSERT INTO api_keys (id, user_id, name, key_hash)
			 VALUES (?, ?, ?, ?)`,
			uid.New(), userID, managedMemberKeyName, hash)
		return err
	}
	return nil
}

// archiveManagedMember archives the managed member and revokes sessions, member
// API keys, and calendar connections. Idempotent.
func (h *Handler) archiveManagedMember(ctx context.Context, sub string) error {
	userID, ok := h.getManagedMemberBySub(ctx, sub)
	if !ok {
		return sql.ErrNoRows
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := h.db.ExecContext(ctx,
		`UPDATE users SET archived_at = ? WHERE id = ?`, now, userID); err != nil {
		return err
	}
	if _, err := h.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return err
	}
	if _, err := h.db.ExecContext(ctx,
		`DELETE FROM api_keys WHERE user_id = ? AND name = ?`,
		userID, managedMemberKeyName); err != nil {
		return err
	}
	if err := h.revokeManagedCalendar(ctx, userID); err != nil {
		return err
	}
	return nil
}

// reactivateManagedMember clears archived_at, keeping the member role.
func (h *Handler) reactivateManagedMember(ctx context.Context, sub string) error {
	userID, ok := h.getManagedMemberBySub(ctx, sub)
	if !ok {
		return sql.ErrNoRows
	}
	if _, err := h.db.ExecContext(ctx,
		`UPDATE users SET archived_at = NULL, is_admin = 0, is_owner = 0, email_login = 0 WHERE id = ?`,
		userID); err != nil {
		return err
	}
	return nil
}

// operatorKeyValid performs a constant-time comparison of the operator key.
func (h *Handler) operatorKeyValid(provided string) bool {
	h.managedMu.RLock()
	expected := h.managedIdentity.operatorKey
	h.managedMu.RUnlock()
	if expected == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// revokeManagedCalendar revokes the user's calendar connections through the
// existing provider revoke boundary. Best-effort; failures are logged.
func (h *Handler) revokeManagedCalendar(ctx context.Context, userID string) error {
	svc := h.getCal()
	if svc == nil {
		return nil
	}
	conns, err := svc.Connections(ctx, userID)
	if err != nil {
		return err
	}
	for _, c := range conns {
		if err := svc.DisconnectOne(ctx, userID, c.ID); err != nil {
			h.logger.WarnContext(ctx, "managed archive: calendar disconnect", "error", err, "user_id", userID, "connection_id", c.ID)
			return err
		}
	}
	return nil
}

// --- sentinel errors and helpers -------------------------------------------

var errIdentityCollision = errors.New("identity collision")

// nullIfEmpty returns a nullable string helper (empty -> NULL).
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// defaultTZ returns tz when valid, else "UTC".
func defaultTZ(tz string) string {
	if tz != "" {
		return tz
	}
	return "UTC"
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	err := decoder.Decode(&struct{}{})
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// isManagedEntryPathSafe validates the entry path stays same-origin (path-only).
func isManagedEntryPathSafe(path string) bool {
	if path == "" {
		return false
	}
	u, err := url.Parse(path)
	if err != nil {
		return false
	}
	return !u.IsAbs() && strings.HasPrefix(path, "/")
}

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint failure.
// (Mirrors the booking package's helper.)
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// hashMemberKey mirrors hashAPIKey for the operator-supplied member key.
func hashMemberKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// ensure rand is linked (used indirectly via uid.New and api key hash).
var _ = rand.Reader
