package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/calnode/calnode/internal/gcal"
)

// InstallManagedGoogleCredential handles PUT /v1/calendar/managed/google.
// The route is wrapped by RequireAuth and additionally requires an API key so
// browser sessions can never submit OAuth material. The API key's user is the
// only possible installation target; there is intentionally no user_id field.
func (h *Handler) InstallManagedGoogleCredential(w http.ResponseWriter, r *http.Request) {
	if !h.bonnieManagedMode {
		h.writeCodedError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if extractAPIKey(r) == "" {
		h.writeCodedError(w, http.StatusForbidden, "api_key_required", "API key required")
		return
	}
	user, ok := userFromContext(r.Context())
	if !ok {
		h.writeCodedError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
		return
	}
	svc := h.getCal()
	if svc == nil {
		h.writeCodedError(w, http.StatusServiceUnavailable, "google_calendar_not_configured", "Google Calendar is not configured")
		return
	}
	client, ok := svc.Provider("google").(*gcal.Client)
	if !ok || client == nil {
		h.writeCodedError(w, http.StatusServiceUnavailable, "google_calendar_not_configured", "Google Calendar is not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var request struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at"`
		AccountEmail string `json:"account_email"`
		CalendarID   string `json:"calendar_id"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid credential request")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid credential request")
		return
	}
	expiry, err := time.Parse(time.RFC3339, strings.TrimSpace(request.ExpiresAt))
	if err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid credential request")
		return
	}
	result, err := client.InstallManagedCredential(r.Context(), user.ID, gcal.ManagedCredential{
		AccessToken:  request.AccessToken,
		RefreshToken: request.RefreshToken,
		Expiry:       expiry,
		AccountEmail: request.AccountEmail,
		CalendarID:   request.CalendarID,
	})
	if err != nil {
		switch {
		case errors.Is(err, gcal.ErrManagedCredentialInvalid):
			h.writeCodedError(w, http.StatusBadRequest, "invalid_google_credential", "Google credential is invalid")
		case errors.Is(err, gcal.ErrManagedMissingScope):
			h.writeCodedError(w, http.StatusUnprocessableEntity, "missing_calendar_scope", "Google Calendar permission is required")
		case errors.Is(err, gcal.ErrManagedClientMismatch):
			h.writeCodedError(w, http.StatusUnprocessableEntity, "oauth_client_mismatch", "Google credential belongs to another application")
		case errors.Is(err, gcal.ErrManagedAccountMismatch):
			h.writeCodedError(w, http.StatusConflict, "google_account_mismatch", "Google account does not match the requested connection")
		default:
			h.logger.ErrorContext(r.Context(), "managed Google credential install failed", "error", err, "user_id", user.ID)
			h.writeCodedError(w, http.StatusBadGateway, "google_validation_failed", "Google credential could not be validated")
		}
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"connected":     true,
		"provider":      "google",
		"account_email": result.AccountEmail,
		"calendar_id":   result.CalendarID,
	})
}

// RevokeManagedGoogleCredential removes the authenticated member's Google
// connection. It is idempotent and never accepts another user's identifier.
func (h *Handler) RevokeManagedGoogleCredential(w http.ResponseWriter, r *http.Request) {
	if !h.bonnieManagedMode {
		h.writeCodedError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if extractAPIKey(r) == "" {
		h.writeCodedError(w, http.StatusForbidden, "api_key_required", "API key required")
		return
	}
	user, ok := userFromContext(r.Context())
	if !ok {
		h.writeCodedError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
		return
	}
	svc := h.getCal()
	if svc == nil {
		h.writeCodedError(w, http.StatusServiceUnavailable, "google_calendar_not_configured", "Google Calendar is not configured")
		return
	}
	client, ok := svc.Provider("google").(*gcal.Client)
	if !ok || client == nil {
		h.writeCodedError(w, http.StatusServiceUnavailable, "google_calendar_not_configured", "Google Calendar is not configured")
		return
	}
	if err := client.Disconnect(r.Context(), user.ID); err != nil {
		h.logger.ErrorContext(r.Context(), "managed Google credential revoke failed", "error", err, "user_id", user.ID)
		h.writeCodedError(w, http.StatusInternalServerError, "credential_revoke_failed", "Calendar connection could not be removed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ManagedGoogleReadiness handles GET /v1/calendar/managed/google/readiness.
// It is API-key only: browser sessions can inspect their calendar but cannot
// use that session as evidence that the exact Bonnie-owned grant is ready.
func (h *Handler) ManagedGoogleReadiness(w http.ResponseWriter, r *http.Request) {
	if !h.bonnieManagedMode {
		h.writeCodedError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if extractAPIKey(r) == "" {
		h.writeCodedError(w, http.StatusForbidden, "api_key_required", "API key required")
		return
	}
	user, ok := userFromContext(r.Context())
	if !ok {
		h.writeCodedError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
		return
	}
	svc := h.getCal()
	if svc == nil {
		h.writeJSON(w, http.StatusOK, map[string]string{
			"provider":  "google",
			"readiness": "provider_unavailable",
		})
		return
	}
	client, ok := svc.Provider("google").(*gcal.Client)
	if !ok || client == nil {
		h.writeJSON(w, http.StatusOK, map[string]string{
			"provider":  "google",
			"readiness": "provider_unavailable",
		})
		return
	}
	result, err := client.ManagedCredentialStatus(r.Context(), user.ID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "managed Google readiness failed", "error", err, "user_id", user.ID)
		h.writeJSON(w, http.StatusOK, map[string]string{
			"provider":  "google",
			"readiness": "provider_unavailable",
		})
		return
	}
	response := map[string]string{
		"provider":  "google",
		"readiness": string(result.Readiness),
	}
	if result.AccountEmail != "" {
		response["account_email"] = result.AccountEmail
	}
	h.writeJSON(w, http.StatusOK, response)
}

func (h *Handler) writeCodedError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]string{"error": message, "code": code})
}
