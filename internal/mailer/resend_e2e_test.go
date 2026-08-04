//go:build e2e

package mailer

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestResendSMTPDelivery is an opt-in live acceptance test. It never prints the
// API key. Set RESEND_API_KEY, EMAIL_FROM_ADDRESS, and RESEND_E2E_TO, then run:
// go test -tags=e2e ./internal/mailer -run TestResendSMTPDelivery
func TestResendSMTPDelivery(t *testing.T) {
	apiKey := os.Getenv("RESEND_API_KEY")
	from := os.Getenv("EMAIL_FROM_ADDRESS")
	to := os.Getenv("RESEND_E2E_TO")
	if apiKey == "" || from == "" || to == "" {
		t.Skip("RESEND_API_KEY, EMAIL_FROM_ADDRESS, and RESEND_E2E_TO are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sender := NewSMTP("smtp.resend.com", "587", "resend", apiKey, false, true, from, "Bonnie")
	if err := sender.Send(ctx, Message{
		To:             []string{to},
		Subject:        "[E2E] Bonnie scheduler email",
		Text:           "Bonnie's Calnode scheduler successfully delivered this Resend SMTP acceptance test.",
		IdempotencyKey: "calnode/e2e/" + time.Now().UTC().Format("20060102T1504"),
	}); err != nil {
		t.Fatalf("Resend SMTP delivery: %v", err)
	}
}
