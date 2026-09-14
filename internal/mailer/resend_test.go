package mailer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResendAPISendPreservesBookingEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/emails" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer re_test_key" {
			t.Error("missing Resend authorization")
		}
		if r.Header.Get("Idempotency-Key") != "calnode/email/delivery-1" {
			t.Error("delivery idempotency key was not forwarded")
		}
		var payload struct {
			From        string   `json:"from"`
			To          []string `json:"to"`
			Subject     string   `json:"subject"`
			Text        string   `json:"text"`
			HTML        string   `json:"html"`
			Attachments []struct {
				Filename    string `json:"filename"`
				Content     string `json:"content"`
				ContentType string `json:"content_type"`
			} `json:"attachments"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		if payload.From != `"Bonnie scheduling" <bonnie@updates.bonniebuilds.com>` ||
			len(payload.To) != 1 || payload.To[0] != "guest@example.com" ||
			payload.Subject != "Booking confirmed" || payload.Text != "plain text" ||
			payload.HTML != "<p>confirmed</p>" {
			t.Errorf("booking email fields changed: %+v", payload)
		}
		if len(payload.Attachments) != 1 || payload.Attachments[0].Filename != "invite.ics" ||
			payload.Attachments[0].ContentType != "text/calendar" ||
			payload.Attachments[0].Content != base64.StdEncoding.EncodeToString([]byte("BEGIN:VCALENDAR")) {
			t.Errorf("calendar attachment changed: %+v", payload.Attachments)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"resend-message-1"}`))
	}))
	defer server.Close()
	sender := NewResendAPI("re_test_key", "bonnie@updates.bonniebuilds.com", "Bonnie scheduling")
	sender.endpoint = server.URL + "/emails"
	if err := sender.Send(context.Background(), Message{
		To: []string{"guest@example.com"}, Subject: "Booking confirmed",
		Text: "plain text", HTML: "<p>confirmed</p>",
		Attachments:    []Attachment{{Filename: "invite.ics", ContentType: "text/calendar", Content: []byte("BEGIN:VCALENDAR")}},
		IdempotencyKey: "calnode/email/delivery-1",
	}); err != nil {
		t.Fatalf("Resend API send: %v", err)
	}
}

func TestResendAPISendRejectsUnacceptedResponse(t *testing.T) {
	for _, test := range []struct {
		name string
		code int
		body string
	}{
		{"provider error", http.StatusForbidden, `{"message":"secret provider detail"}`},
		{"missing receipt", http.StatusOK, `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.code)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			sender := NewResendAPI("re_test_key", "bonnie@updates.bonniebuilds.com", "Bonnie")
			sender.endpoint = server.URL
			err := sender.Send(context.Background(), Message{To: []string{"guest@example.com"}, Subject: "test", Text: "test"})
			if err == nil || strings.Contains(err.Error(), "secret provider detail") {
				t.Errorf("Send error = %v; want safe failure", err)
			}
		})
	}
}
