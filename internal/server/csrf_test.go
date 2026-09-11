package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// runSameOrigin sends r through SameOriginCheck and returns (statusCode, nextCalled).
func runSameOrigin(r *http.Request) (int, bool) {
	called := false
	h := SameOriginCheck(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, called
}

func csrfReq(method, origin string, withCookie bool) *http.Request {
	r := httptest.NewRequest(method, "http://app.example.com/v1/teams", nil)
	r.Host = "app.example.com"
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if withCookie {
		r.AddCookie(&http.Cookie{Name: "calnode_session", Value: "sess"})
	}
	return r
}

func TestSameOrigin_blocksCrossOriginCookieWrite(t *testing.T) {
	code, called := runSameOrigin(csrfReq(http.MethodPost, "http://evil.example.net", true))
	if code != http.StatusForbidden {
		t.Errorf("status = %d; want 403", code)
	}
	if called {
		t.Error("next handler should not run for a blocked cross-origin write")
	}
}

func TestSameOrigin_blocksCrossOriginLocalManagedCookieWrite(t *testing.T) {
	r := csrfReq(http.MethodPost, "http://evil.example.net", false)
	r.AddCookie(&http.Cookie{Name: "calnode_session_local", Value: "local-session"})
	code, called := runSameOrigin(r)
	if code != http.StatusForbidden || called {
		t.Fatalf("local managed browser cookie must retain CSRF protection: status=%d called=%v", code, called)
	}
}

func TestSameOrigin_blocksLegacyManagedExchangePaths(t *testing.T) {
	paths := []string{
		"/v1/auth/managed/exchange",
		"/v1/auth/managed/exchange/calendar/embed",
		"/v1/auth/managed/exchange/calendar/full",
	}
	for _, path := range paths {
		r := httptest.NewRequest(http.MethodPost, "http://scheduler.example.com"+path, nil)
		r.Host = "scheduler.example.com"
		r.Header.Set("Origin", "https://app.example.com")
		r.AddCookie(&http.Cookie{Name: "calnode_session", Value: "stale-or-active-session"})
		code, called := runSameOrigin(r)
		if code != http.StatusForbidden || called {
			t.Fatalf("removed managed assertion exchange %q must have no CSRF exemption: status=%d called=%v", path, code, called)
		}
	}
}

func TestSameOrigin_doesNotExemptManagedExchangeLookalikes(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://scheduler.example.com/v1/auth/managed/exchange/calendar/embed/extra", nil)
	r.Host = "scheduler.example.com"
	r.Header.Set("Origin", "https://app.example.com")
	r.AddCookie(&http.Cookie{Name: "calnode_session", Value: "session"})
	code, called := runSameOrigin(r)
	if code != http.StatusForbidden || called {
		t.Fatalf("managed exchange lookalike must remain blocked: status=%d called=%v", code, called)
	}
}

func TestSameOrigin_allowsSameOriginCookieWrite(t *testing.T) {
	code, called := runSameOrigin(csrfReq(http.MethodPost, "http://app.example.com", true))
	if code != http.StatusOK || !called {
		t.Errorf("same-origin write should pass: status=%d called=%v", code, called)
	}
}

func TestSameOrigin_allowsWriteWithoutSessionCookie(t *testing.T) {
	// Public booking POST / API-key clients carry no session cookie — never blocked.
	code, called := runSameOrigin(csrfReq(http.MethodPost, "http://evil.example.net", false))
	if code != http.StatusOK || !called {
		t.Errorf("no-cookie write should pass: status=%d called=%v", code, called)
	}
}

func TestSameOrigin_allowsGetEvenCrossOrigin(t *testing.T) {
	code, called := runSameOrigin(csrfReq(http.MethodGet, "http://evil.example.net", true))
	if code != http.StatusOK || !called {
		t.Errorf("GET should pass regardless of origin: status=%d called=%v", code, called)
	}
}

func TestSameOrigin_allowsWhenNoOriginOrReferer(t *testing.T) {
	// Neither header present → can't determine cross-origin; SameSite=Lax is the guard.
	code, called := runSameOrigin(csrfReq(http.MethodPost, "", true))
	if code != http.StatusOK || !called {
		t.Errorf("missing Origin/Referer should pass: status=%d called=%v", code, called)
	}
}

func TestSameOrigin_fallsBackToReferer(t *testing.T) {
	r := csrfReq(http.MethodDelete, "", true) // no Origin
	r.Header.Set("Referer", "http://evil.example.net/some/page")
	code, called := runSameOrigin(r)
	if code != http.StatusForbidden || called {
		t.Errorf("cross-origin Referer should block: status=%d called=%v", code, called)
	}
}

func TestAvailabilityAssertionExchangeIsTheOnlyNewCrossOriginException(t *testing.T) {
	for _, path := range []string{"/v1/auth/managed/availability", "/v1/availability-rules"} {
		r := csrfReq(http.MethodPost, "https://bonnie.example", true)
		r.URL.Path = path
		code, called := runSameOrigin(r)
		if path == "/v1/auth/managed/availability" {
			if code != 200 || !called {
				t.Fatal("signed assertion exchange blocked by stale browser cookie")
			}
		} else if code != 403 || called {
			t.Fatal("ordinary availability write lost CSRF protection")
		}
	}
}
