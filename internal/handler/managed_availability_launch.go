package handler

import (
	"net/http"
	"time"
)

// ManagedAvailabilityExchange exchanges a one-time Bonnie assertion for the
// existing member's session, with a fixed availability destination.
func (h *Handler) ManagedAvailabilityExchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !h.bonnieManagedMode {
		h.writeCodedError(w, 404, "not_found", "not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, managedAssertionMaxBody)
	if err := r.ParseForm(); err != nil || len(r.PostForm) != 1 || len(r.PostForm["assertion"]) != 1 {
		h.writeCodedError(w, 400, "invalid_request", "invalid launch request")
		return
	}
	claims, err := h.verifyManagedAssertion(r.Context(), r.PostForm.Get("assertion"))
	if err != nil {
		h.writeCodedError(w, 401, "managed_assertion_rejected", "assertion rejected")
		return
	}
	consumed, err := h.consumeJTI(r.Context(), claims.JTI)
	if err != nil {
		h.writeCodedError(w, 503, "launch_unavailable", "availability editor unavailable")
		return
	}
	if !consumed {
		h.writeCodedError(w, 401, "managed_assertion_rejected", "assertion rejected")
		return
	}
	userID, found := h.getActiveManagedMemberBySub(r.Context(), claims.Sub)
	if !found {
		h.writeCodedError(w, 403, "member_unavailable", "member unavailable")
		return
	}
	h.managedMu.RLock()
	ttl := h.managedIdentity.sessionTTL
	h.managedMu.RUnlock()
	if ttl <= 0 || ttl > time.Hour {
		ttl = time.Hour
	}
	if err := h.createSessionTTL(r.Context(), w, userID, ttl, true); err != nil {
		h.writeCodedError(w, 503, "launch_unavailable", "availability editor unavailable")
		return
	}
	http.Redirect(w, r, "/admin/availability", http.StatusSeeOther)
}
