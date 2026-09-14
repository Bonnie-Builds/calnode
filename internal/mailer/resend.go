package mailer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"time"
)

// ResendAPI sends deployment-owned mail over HTTPS, including calendar attachments.
type ResendAPI struct {
	apiKey   string
	from     string
	fromName string
	endpoint string
	client   *http.Client
}

// NewResendAPI constructs the Resend transport for a deployment API key.
func NewResendAPI(apiKey, from, fromName string) *ResendAPI {
	return &ResendAPI{
		apiKey: apiKey, from: from, fromName: fromName,
		endpoint: "https://api.resend.com/emails",
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *ResendAPI) Send(ctx context.Context, msg Message) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("mailer: resend API requires a recipient")
	}
	type attachment struct {
		Filename    string `json:"filename"`
		Content     string `json:"content"`
		ContentType string `json:"content_type,omitempty"`
	}
	attachments := make([]attachment, 0, len(msg.Attachments))
	for _, item := range msg.Attachments {
		attachments = append(attachments, attachment{
			Filename: item.Filename, Content: base64.StdEncoding.EncodeToString(item.Content),
			ContentType: item.ContentType,
		})
	}
	body, err := json.Marshal(struct {
		From        string       `json:"from"`
		To          []string     `json:"to"`
		Subject     string       `json:"subject"`
		Text        string       `json:"text"`
		HTML        string       `json:"html,omitempty"`
		Attachments []attachment `json:"attachments,omitempty"`
	}{
		From: (&mail.Address{Name: s.fromName, Address: s.from}).String(),
		To:   msg.To, Subject: msg.Subject, Text: msg.Text, HTML: msg.HTML,
		Attachments: attachments,
	})
	if err != nil {
		return fmt.Errorf("mailer: encode resend API request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("mailer: create resend API request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+s.apiKey)
	request.Header.Set("Content-Type", "application/json")
	if msg.IdempotencyKey != "" {
		request.Header.Set("Idempotency-Key", msg.IdempotencyKey)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("mailer: resend API request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("mailer: resend API returned HTTP %d", response.StatusCode)
	}
	var accepted struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&accepted); err != nil || accepted.ID == "" {
		return fmt.Errorf("mailer: resend API did not confirm acceptance")
	}
	return nil
}
