package handler

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeManagedFrameAncestorsRequiresExactHTTPSOrLoopbackSiteOrigins(t *testing.T) {
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

	loopback := normalizeManagedFrameAncestors([]string{
		"http://localhost:5420",
		"http://attacker.example.net:5420",
	}, "localhost")
	if want := []string{"http://localhost:5420"}; !reflect.DeepEqual(loopback, want) {
		t.Fatalf("loopback origins = %#v; want %#v", loopback, want)
	}
}

func TestExactHTTPLoopbackOriginRejectsRemoteAndDecoratedURLs(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "http://localhost:4222", want: true},
		{value: "http://127.0.0.1:4222", want: true},
		{value: "http://[::1]:4222", want: true},
		{value: "https://localhost:4222", want: false},
		{value: "http://scheduler.example.com", want: false},
		{value: "http://localhost.evil.example:4222", want: false},
		{value: "http://localhost:4222/path", want: false},
		{value: "http://user@localhost:4222", want: false},
	}
	for _, test := range tests {
		if got := isExactHTTPLoopbackOrigin(test.value); got != test.want {
			t.Fatalf("isExactHTTPLoopbackOrigin(%q) = %t; want %t", test.value, got, test.want)
		}
	}
}

func TestManagedBookingPagePolicyFailsClosedAndAllowsOnlyNormalizedOrigins(t *testing.T) {
	h := &Handler{}
	csp, frameAllowed := h.managedBookingPagePolicy(trackingSettings{})
	if frameAllowed || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("empty policy = (%q, %t); want fail-closed", csp, frameAllowed)
	}

	h.SetManagedIdentityConfig(ManagedIdentityConfig{
		SiteDomain: "example.com",
		BookingFrameAncestors: []string{
			"https://app.example.com",
			"https://attacker.example.net",
			"https://*.example.com",
		},
	})
	csp, frameAllowed = h.managedBookingPagePolicy(trackingSettings{})
	if !frameAllowed || !strings.Contains(csp, "frame-ancestors https://app.example.com") {
		t.Fatalf("qualified policy = (%q, %t); want exact Bonnie origin", csp, frameAllowed)
	}
	if strings.Contains(csp, "attacker") || strings.Contains(csp, "*") {
		t.Fatalf("qualified policy = %q; contains hostile or wildcard origin", csp)
	}
}
