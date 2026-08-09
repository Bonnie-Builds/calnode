package handler

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeManagedFrameAncestorsRequiresExactHTTPSSiteOrigins(t *testing.T) {
	got := normalizeManagedFrameAncestors([]string{
		"https://app.acme.example.com",
		"https://app.acme.example.com/",
		"https://context.acme.example.com:8443",
		"http://app.acme.example.com",
		"https://attacker.example.net",
		"https://*.acme.example.com",
		"https://app.acme.example.com/path",
	}, "example.com")
	want := []string{"https://app.acme.example.com", "https://context.acme.example.com:8443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("origins = %#v; want %#v", got, want)
	}
}

func TestManagedCalendarEmbedCSPFailsClosedWithoutQualifiedOrigins(t *testing.T) {
	h := &Handler{}
	if got := h.managedCalendarEmbedCSP(); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("CSP = %q; want frame-ancestors 'none'", got)
	}
	h.managedIdentity.frameAncestors = []string{"https://app.example.com"}
	got := h.managedCalendarEmbedCSP()
	if !strings.Contains(got, "frame-ancestors https://app.example.com") || strings.Contains(got, "*") {
		t.Fatalf("CSP = %q; want exact ancestor without wildcard", got)
	}
}
