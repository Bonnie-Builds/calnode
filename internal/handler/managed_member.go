package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

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
