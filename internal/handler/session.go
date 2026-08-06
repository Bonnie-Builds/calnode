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
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly/SameSite/Secure are all set; Secure is h.secureCookie (true whenever BASE_URL is https, false only for local http dev) rather than a literal, which gosec's static check can't verify
		Name:     sessionCookieName,
		Value:    sessID,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.secureCookie || managed,
	})
	return nil
}
