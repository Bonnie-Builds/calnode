package mailer

import "context"

// Attachment is a file attached to an outbound email.
type Attachment struct {
	Filename    string
	ContentType string // full MIME type, e.g. `text/calendar; charset=utf-8; method=REQUEST`
	Content     []byte
}

// Message is an outbound email.
type Message struct {
	To          []string
	Subject     string
	Text        string // plain-text body (always set; used as the fallback alternative)
	HTML        string // optional HTML body; when set the message is multipart/alternative
	Attachments []Attachment
	// IdempotencyKey deduplicates enqueue attempts. The durable worker replaces it
	// with a delivery-specific key before talking to the provider, so every retry
	// of one delivery is safe while separate lifecycle events remain distinct.
	IdempotencyKey string
}

// Mailer sends email messages.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// Noop silently discards all messages. Used when SMTP is not configured.
type Noop struct{}

func (n *Noop) Send(_ context.Context, _ Message) error { return nil }
