package server

import (
	"os"
	"strings"
	"testing"
)

func TestGoogleProviderCustodyRemainsInsideCalnode(t *testing.T) {
	serverSource, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	calendarSource, err := os.ReadFile("../handler/calendar.go")
	if err != nil {
		t.Fatal(err)
	}
	joined := string(serverSource) + "\n" + string(calendarSource)
	for _, forbidden := range []string{
		"/v1/calendar/managed/google",
		"managed_by_bonnie",
		"BONNIE_CUSTODY_TRANSPORT_URL",
		"serviceAccounts.signJwt",
		"google_dwd_v1",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Google provider custody escaped Calnode through %q", forbidden)
		}
	}
	if _, err := os.Stat("../custody/custody.go"); !os.IsNotExist(err) {
		t.Fatal("Bonbon calendar-effect transport must not exist in Calnode")
	}
}

