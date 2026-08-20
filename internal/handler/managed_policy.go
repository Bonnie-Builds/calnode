package handler

import (
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// managedLoginRedirect returns the configured Bonnie launch URL, or "".
func (h *Handler) managedLoginRedirect() string {
	h.managedMu.RLock()
	defer h.managedMu.RUnlock()
	return h.managedIdentity.loginRedirect
}

// hasValidSession reports whether the request carries an unexpired session
// cookie for an active (non-archived) user.
func (h *Handler) hasValidSession(r *http.Request) bool {
	cookie, err := h.browserSessionCookie(r)
	if err != nil || cookie.Value == "" {
		return false
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var n int
	if err := h.db.QueryRowContext(r.Context(), `
		SELECT COUNT(*) FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.id = ? AND s.expires_at > ? AND u.archived_at IS NULL`,
		cookie.Value, now).Scan(&n); err != nil || n == 0 {
		return false
	}
	return true
}

// ManagedSPAGuard wraps the admin SPA in managed mode: an unauthenticated
// browser is redirected to the Bonnie launch surface instead of the native
// login page. In non-managed mode it passes through unchanged.
func (h *Handler) ManagedSPAGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.bonnieManagedMode {
			if !h.hasValidSession(r) {
				if target := h.managedLoginRedirect(); target != "" {
					http.Redirect(w, r, target, http.StatusSeeOther)
					return
				}
				h.writeCodedError(w, http.StatusServiceUnavailable, "managed_login_unavailable", "managed login unavailable")
				return
			}
			if r.URL.Path == "/calendar/personal/embed" {
				w.Header().Set("Content-Security-Policy", h.managedCalendarEmbedCSP())
			}
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeManagedFrameAncestors(origins []string, siteDomain string) []string {
	site := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(siteDomain), "."))
	if site == "" {
		return nil
	}
	seen := make(map[string]struct{}, len(origins))
	normalized := make([]string, 0, len(origins))
	for _, raw := range origins {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		hostname := strings.ToLower(parsed.Hostname())
		loopback := isLoopbackHostname(hostname)
		qualifiedScheme := parsed.Scheme == "https" || (parsed.Scheme == "http" && loopback)
		if !qualifiedScheme || parsed.Host == "" || strings.Contains(parsed.Host, "*") || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			continue
		}
		if hostname != site && !strings.HasSuffix(hostname, "."+site) {
			continue
		}
		origin := parsed.Scheme + "://" + parsed.Host
		if _, exists := seen[origin]; exists {
			continue
		}
		seen[origin] = struct{}{}
		normalized = append(normalized, origin)
	}
	sort.Strings(normalized)
	return normalized
}

func isLoopbackHostname(hostname string) bool {
	normalized := strings.ToLower(strings.TrimSpace(hostname))
	parsedIP := net.ParseIP(normalized)
	return normalized == "localhost" || (parsedIP != nil && parsedIP.IsLoopback())
}

func isExactHTTPLoopbackOrigin(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return isLoopbackHostname(parsed.Hostname())
}

func (h *Handler) managedCalendarEmbedCSP() string {
	h.managedMu.RLock()
	ancestors := append([]string(nil), h.managedIdentity.frameAncestors...)
	scriptSources := append([]string(nil), h.managedIdentity.scriptSources...)
	h.managedMu.RUnlock()
	frameAncestors := "'none'"
	if len(ancestors) > 0 {
		frameAncestors = strings.Join(ancestors, " ")
	}
	scriptSource := "'self'"
	if len(scriptSources) > 0 {
		scriptSource += " " + strings.Join(scriptSources, " ")
	}
	return "default-src 'self'; script-src " + scriptSource + "; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors " + frameAncestors + "; base-uri 'none'; form-action 'self'"
}

// managedBookingPagePolicy returns the public booking-page CSP and whether an
// exact, deployment-qualified Bonnie ancestor exists. The caller omits the
// legacy X-Frame-Options header only in that explicitly configured case because
// X-Frame-Options has no interoperable exact-origin allowlist form.
func (h *Handler) managedBookingPagePolicy(t trackingSettings) (string, bool) {
	h.managedMu.RLock()
	ancestors := append([]string(nil), h.managedIdentity.bookingFrameAncestors...)
	h.managedMu.RUnlock()
	return publicCSPWithFrameAncestors(t, ancestors), len(ancestors) > 0
}

// ManagedRoot handles GET / in managed mode: an unauthenticated browser is
// redirected to the Bonnie launch surface; an authenticated managed member is
// sent to the configured entry path. Non-managed mode falls through to the
// normal /admin redirect.
func (h *Handler) ManagedRoot(w http.ResponseWriter, r *http.Request) {
	if h.bonnieManagedMode {
		if !h.hasValidSession(r) {
			if target := h.managedLoginRedirect(); target != "" {
				http.Redirect(w, r, target, http.StatusSeeOther)
				return
			}
			h.writeCodedError(w, http.StatusServiceUnavailable, "managed_login_unavailable", "managed login unavailable")
			return
		}
		h.managedMu.RLock()
		entry := h.managedIdentity.entryPath
		h.managedMu.RUnlock()
		if entry == "" || entry == "/" || !isManagedEntryPathSafe(entry) {
			entry = "/admin/"
		}
		http.Redirect(w, r, entry, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusFound)
}

// managedDenyRoute matches an HTTP method + path pattern against the managed
// surface denial policy. Patterns use the same `{param}` shape as the router
// for readability, but matching is intentionally literal on the path prefix —
// the middleware is a coarse second gate; the route-level policy below is the
// precise one.
type managedDenyRule struct {
	method string // "" matches any method
	prefix string // path prefix to deny
}

// managedDeniedRoutes are the native/admin/developer/provider-consent surfaces
// that managed members can never reach (server-side denial).
var managedDeniedRoutes = []managedDenyRule{
	// Native auth / claim / invite
	{method: "POST", prefix: "/v1/auth/claim"},
	{method: "POST", prefix: "/v1/auth/login"},
	{method: "GET", prefix: "/v1/auth/login"},
	{method: "GET", prefix: "/v1/auth/callback"},
	{method: "POST", prefix: "/v1/auth/magic-link"},
	{method: "GET", prefix: "/v1/auth/magic-link"},
	{method: "POST", prefix: "/v1/auth/microsoft/login"},
	{method: "GET", prefix: "/v1/auth/microsoft/login"},
	{method: "POST", prefix: "/v1/invites"},
	{method: "GET", prefix: "/v1/invites"},
	{method: "POST", prefix: "/v1/invites/"},
	{method: "GET", prefix: "/v1/invites/"},
	// Users / roles / ownership
	{method: "GET", prefix: "/v1/users"},
	{method: "DELETE", prefix: "/v1/users/"},
	{method: "PATCH", prefix: "/v1/users/"},
	{method: "POST", prefix: "/v1/users/"},
	// Teams / workspace settings
	{method: "POST", prefix: "/v1/teams"},
	{method: "GET", prefix: "/v1/teams"},
	{method: "PATCH", prefix: "/v1/teams"},
	{method: "DELETE", prefix: "/v1/teams"},
	// Settings surfaces (workspace-global, branding, email, providers, etc.)
	{method: "GET", prefix: "/v1/settings"},
	{method: "PATCH", prefix: "/v1/settings"},
	{method: "POST", prefix: "/v1/settings"},
	// API keys (create/delete), webhooks, connected apps / MCP / OAuth
	{method: "POST", prefix: "/v1/api-keys"},
	{method: "POST", prefix: "/v1/webhooks"},
	{method: "PATCH", prefix: "/v1/webhooks/"},
	{method: "DELETE", prefix: "/v1/webhooks/"},
	{method: "GET", prefix: "/v1/webhooks"},
	{method: "GET", prefix: "/v1/oauth/connections"},
	{method: "DELETE", prefix: "/v1/oauth/connections/"},
	{method: "POST", prefix: "/oauth/register"},
	{method: "GET", prefix: "/oauth/authorize"},
	{method: "POST", prefix: "/oauth/authorize"},
	{method: "POST", prefix: "/oauth/token"},
	{method: "POST", prefix: "/mcp"},
	{method: "GET", prefix: "/mcp"},
	// Native provider-consent connect/callback routes
	{method: "GET", prefix: "/v1/calendar/connect"},
	{method: "GET", prefix: "/v1/calendar/callback"},
	{method: "GET", prefix: "/v1/zoom/connect"},
	{method: "GET", prefix: "/v1/zoom/callback"},
	{method: "POST", prefix: "/v1/calendar/caldav/connect"},
	// Demo surfaces
	{method: "GET", prefix: "/v1/demo/enter"},
	{method: "POST", prefix: "/v1/demo/reset"},
}

// ManagedDenyMiddleware applies the managed-mode surface policy to the whole
// mux. In managed mode, a caller authenticated as a managed member (non-admin,
// non-owner) is denied the hidden native/admin/developer/provider-consent
// routes before they reach the router. The operator-key endpoints are exempt
// (they authenticate separately via RequireManagedOperator) and public booking
// surfaces are never denied. In non-managed mode it is a no-op.
func (h *Handler) ManagedDenyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.bonnieManagedMode {
			// Only browser-session callers can be managed members; API-key callers
			// resolve through RequireAuth and the managed member flag there. Here we
			// resolve the session cookie directly so denial happens before routing.
			if user, ok := h.managedCaller(r); ok && user.IsManagedMember && !user.IsAdmin && !user.IsOwner {
				if isManagedPersonalUserRoute(r.Method, r.URL.Path) {
					next.ServeHTTP(w, r)
					return
				}
				for _, rule := range managedDeniedRoutes {
					if rule.method != "" && rule.method != r.Method {
						continue
					}
					if len(r.URL.Path) >= len(rule.prefix) && r.URL.Path[:len(rule.prefix)] == rule.prefix {
						h.writeCodedError(w, http.StatusNotFound, "not_found", "not found")
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// managedCaller resolves the session-cookie caller as an AuthUser, mirroring
// the session path in RequireAuth. Returns ok=false when no valid session.
func (h *Handler) managedCaller(r *http.Request) (AuthUser, bool) {
	cookie, err := h.browserSessionCookie(r)
	if err == nil && cookie.Value != "" {
		if user, ok := h.managedSessionCaller(r, cookie.Value); ok {
			return user, true
		}
	}
	rawKey := r.Header.Get("X-API-Key")
	if rawKey == "" {
		rawKey = r.Header.Get("Authorization")
		if len(rawKey) > 7 && rawKey[:7] == "Bearer " {
			rawKey = rawKey[7:]
		} else {
			rawKey = ""
		}
	}
	if rawKey == "" {
		return AuthUser{}, false
	}
	return h.managedAPIKeyCaller(r, rawKey)
}

func (h *Handler) managedSessionCaller(r *http.Request, sessionID string) (AuthUser, bool) {
	now := time.Now().UTC().Format(time.RFC3339)
	var user AuthUser
	var nc, nca, nr, nrm, nhb, nhc, nhr int
	err := h.db.QueryRowContext(r.Context(), `
		SELECT u.id, u.email, u.name, u.iana_timezone, u.time_format, u.week_start, u.date_format, COALESCE(u.avatar_url,''), u.is_admin, u.is_owner, COALESCE(u.is_managed_member,0),
		       COALESCE(u.notify_confirmation,1), COALESCE(u.notify_cancellation,1), COALESCE(u.notify_reschedule,1), COALESCE(u.notify_reminder,1),
		       COALESCE(u.notify_host_booking,1), COALESCE(u.notify_host_cancel,1), COALESCE(u.notify_host_reschedule,1)
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.id = ? AND s.expires_at > ? AND u.archived_at IS NULL`,
		sessionID, now).
		Scan(&user.ID, &user.Email, &user.Name, &user.IANATZ, &user.TimeFormat, &user.WeekStart, &user.DateFormat, &user.AvatarURL, &user.IsAdmin, &user.IsOwner, &user.IsManagedMember,
			&nc, &nca, &nr, &nrm, &nhb, &nhc, &nhr)
	if err != nil {
		return AuthUser{}, false
	}
	user.NotifyConfirmation, user.NotifyCancellation, user.NotifyReschedule, user.NotifyReminder = nc != 0, nca != 0, nr != 0, nrm != 0
	user.NotifyHostBooking, user.NotifyHostCancel, user.NotifyHostReschedule = nhb != 0, nhc != 0, nhr != 0
	return user, true
}

func (h *Handler) managedAPIKeyCaller(r *http.Request, rawKey string) (AuthUser, bool) {
	var user AuthUser
	err := h.db.QueryRowContext(r.Context(), `
		SELECT u.id, u.email, u.name, u.is_admin, u.is_owner, COALESCE(u.is_managed_member,0)
		FROM api_keys ak JOIN users u ON u.id = ak.user_id
		WHERE ak.key_hash = ? AND u.archived_at IS NULL`, hashAPIKey(rawKey)).
		Scan(&user.ID, &user.Email, &user.Name, &user.IsAdmin, &user.IsOwner, &user.IsManagedMember)
	if err != nil {
		return AuthUser{}, false
	}
	return user, true
}

func isManagedPersonalUserRoute(method, path string) bool {
	if path == "/v1/users/me" {
		return method == http.MethodGet || method == http.MethodPatch
	}
	if path == "/v1/users/me/avatar" {
		return method == http.MethodPost || method == http.MethodDelete
	}
	return false
}
