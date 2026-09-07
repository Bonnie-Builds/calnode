package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type managedWebhookProvisioningKey struct{}

// RequireManagedOperator authenticates the deployment-owned operator key. The
// managed member endpoints are reachable ONLY through this key, never a browser
// session or member API key.
func (h *Handler) RequireManagedOperator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.bonnieManagedMode {
			h.writeCodedError(w, http.StatusNotFound, "not_found", "not found")
			return
		}
		provided := r.Header.Get("X-Operator-Key")
		if !h.operatorKeyValid(provided) {
			h.writeCodedError(w, http.StatusUnauthorized, "operator_key_required", "operator key required")
			return
		}
		next(w, r)
	}
}

// ManagedEnsureMember handles POST /v1/managed/members. The operator supplies
// the stable Bonnie subject, identity, and a Bonbon-generated member API key
// whose hash is stored; the member is upserted idempotently.
func (h *Handler) ManagedEnsureMember(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxOperatorBody)
	var req struct {
		Sub          string `json:"sub"`
		Email        string `json:"email"`
		Name         string `json:"name"`
		MemberAPIKey string `json:"member_api_key"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid member request")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid member request")
		return
	}

	userID, err := h.ensureManagedMember(r.Context(), req.Sub, req.Email, req.Name, req.MemberAPIKey)
	if err != nil {
		h.logger.WarnContext(r.Context(), "managed member ensure failed", "error", err)
		if errors.Is(err, errIdentityCollision) {
			h.writeCodedError(w, http.StatusConflict, "identity_collision", "identity collision")
			return
		}
		if strings.Contains(err.Error(), "missing fields") || strings.Contains(err.Error(), "invalid email") || strings.Contains(err.Error(), "too short") {
			h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid member request")
			return
		}
		h.writeCodedError(w, http.StatusServiceUnavailable, "member_unavailable", "member unavailable")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"sub":  req.Sub,
		"role": "member",
	})
	_ = userID
}

// ManagedRebindMember handles POST /v1/managed/members/{sub}/rebind. It is an
// explicit operator-only migration from a legacy managed subject to a new
// stable subject. The Calnode user row is retained, so provider connections
// stay in Calnode custody, while the caller-supplied member key is rotated.
func (h *Handler) ManagedRebindMember(w http.ResponseWriter, r *http.Request) {
	previousSub := strings.TrimSpace(r.PathValue("sub"))
	r.Body = http.MaxBytesReader(w, r.Body, maxOperatorBody)
	var req struct {
		NewSub       string `json:"new_sub"`
		MemberAPIKey string `json:"member_api_key"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid rebind request")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid rebind request")
		return
	}
	if err := h.rebindManagedMember(r.Context(), previousSub, req.NewSub, req.MemberAPIKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.writeCodedError(w, http.StatusNotFound, "member_not_found", "managed member not found")
			return
		}
		if errors.Is(err, errIdentityCollision) {
			h.writeCodedError(w, http.StatusConflict, "identity_collision", "identity collision")
			return
		}
		if strings.Contains(err.Error(), "invalid rebind") || strings.Contains(err.Error(), "too short") {
			h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid rebind request")
			return
		}
		h.logger.ErrorContext(r.Context(), "managed member rebind failed", "error", err)
		h.writeCodedError(w, http.StatusServiceUnavailable, "member_unavailable", "member unavailable")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"sub": req.NewSub, "role": "member"})
}

// ManagedArchiveMember handles POST /v1/managed/members/{sub}/archive.
func (h *Handler) ManagedArchiveMember(w http.ResponseWriter, r *http.Request) {
	sub := r.PathValue("sub")
	err := h.archiveManagedMember(r.Context(), sub)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.writeCodedError(w, http.StatusNotFound, "member_not_found", "managed member not found")
			return
		}
		h.logger.ErrorContext(r.Context(), "managed member archive failed", "error", err)
		h.writeCodedError(w, http.StatusServiceUnavailable, "member_unavailable", "member unavailable")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"sub": sub, "archived": true})
}

// ManagedReactivateMember handles POST /v1/managed/members/{sub}/reactivate.
func (h *Handler) ManagedReactivateMember(w http.ResponseWriter, r *http.Request) {
	sub := r.PathValue("sub")
	err := h.reactivateManagedMember(r.Context(), sub)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.writeCodedError(w, http.StatusNotFound, "member_not_found", "managed member not found")
			return
		}
		h.logger.ErrorContext(r.Context(), "managed member reactivate failed", "error", err)
		h.writeCodedError(w, http.StatusServiceUnavailable, "member_unavailable", "member unavailable")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"sub": sub, "reactivated": true})
}

// ManagedCreateMemberWebhook handles POST
// /v1/managed/members/{sub}/webhooks. The deployment operator may create a
// webhook owned by exactly one active managed member without exposing webhook
// administration to that member's browser session or API key.
func (h *Handler) ManagedCreateMemberWebhook(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimSpace(r.PathValue("sub"))
	if sub == "" || len(sub) > 512 {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid managed subject")
		return
	}

	var userID string
	err := h.db.QueryRowContext(r.Context(), `
		SELECT id FROM users
		WHERE managed_subject = ?
		  AND is_managed_member = 1
		  AND archived_at IS NULL`, sub).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		h.writeCodedError(w, http.StatusNotFound, "member_not_found", "managed member not found")
		return
	}
	if err != nil {
		h.logger.ErrorContext(r.Context(), "managed member webhook lookup failed", "error", err)
		h.writeCodedError(w, http.StatusServiceUnavailable, "member_unavailable", "member unavailable")
		return
	}

	ctx := context.WithValue(r.Context(), ctxKeyUser, AuthUser{
		ID:              userID,
		IsManagedMember: true,
	})
	ctx = context.WithValue(ctx, managedWebhookProvisioningKey{}, true)
	h.CreateWebhook(w, r.WithContext(ctx))
}
