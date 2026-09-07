package handler

import "net/http"

func (h *Handler) writeCodedError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]string{"error": message, "code": code})
}
