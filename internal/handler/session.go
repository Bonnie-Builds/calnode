package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// createSession inserts a session row and sets the session cookie on w.
func (h *Handler) createSession(ctx context.Context, w http.ResponseWriter, userID string) error {
	return h.createSessionTTL(ctx, w, userID, sessionDuration, false)
}

// createSessionTTL inserts a session row with an explicit TTL and sets the
// session cookie. managed marks the session as managed (<=1h, deprovisioned on
// member archive).
func (h *Handler) createSessionTTL(ctx context.Context, w http.ResponseWriter, userID string, ttl time.Duration, managed bool) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	sessID := hex.EncodeToString(raw)
	expiresAt := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	managedFlag := 0
	if managed {
		managedFlag = 1
	}
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, managed) VALUES (?, ?, ?, ?)`,
		sessID, userID, expiresAt, managedFlag); err != nil {
		return err
	}
	secure := h.sessionCookieSecure(managed)
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly/SameSite are fixed; Secure stays mandatory except for an exact HTTP loopback managed origin used by local manual QA
		Name:     h.sessionCookieName(managed),
		Value:    sessID,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
	return nil
}

func (h *Handler) sessionCookieName(managed bool) string {
	if managed && !h.sessionCookieSecure(true) {
		return loopbackManagedSessionCookieName
	}
	return sessionCookieName
}

func (h *Handler) browserSessionCookieName() string {
	return h.sessionCookieName(h.bonnieManagedMode)
}

func (h *Handler) browserSessionCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie(h.browserSessionCookieName())
}

func (h *Handler) sessionCookieSecure(managed bool) bool {
	if !managed {
		return h.secureCookie
	}
	h.managedMu.RLock()
	publicBaseURL := h.managedIdentity.publicBaseURL
	h.managedMu.RUnlock()
	return h.secureCookie || !isExactHTTPLoopbackOrigin(publicBaseURL)
}
