package worker_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/calnode/calnode/internal/mailer"
	"github.com/calnode/calnode/internal/worker"
)

type failingMailer struct {
	attempts int
}

func (m *failingMailer) Send(_ context.Context, _ mailer.Message) error {
	m.attempts++
	return errors.New("provider unavailable")
}

func TestWorkerAcceptsQueuedEmailWithStableProviderKey(t *testing.T) {
	database, svc := setup(t)
	queue := mailer.NewQueue(database)
	if err := queue.Send(context.Background(), mailer.Message{
		To: []string{"person@example.com"}, Subject: "Hello", Text: "Body",
		IdempotencyKey: "test/accepted",
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	capture := &captureMailer{}
	w := worker.New(database, svc, slog.Default(), worker.WithMailer(capture),
		worker.WithHTTPClient(&http.Client{}))
	w.Poll(context.Background())

	if len(capture.sent) != 1 {
		t.Fatalf("sent=%d; want 1", len(capture.sent))
	}
	if capture.sent[0].IdempotencyKey == "" {
		t.Fatal("provider send is missing its stable idempotency key")
	}
	var deliveryStatus, jobStatus string
	database.QueryRow(`SELECT status FROM email_deliveries LIMIT 1`).Scan(&deliveryStatus)            // #nosec G104 -- asserted below
	database.QueryRow(`SELECT status FROM jobs WHERE type = ?`, mailer.EmailJobType).Scan(&jobStatus) // #nosec G104 -- asserted below
	if deliveryStatus != "accepted" || jobStatus != "done" {
		t.Fatalf("delivery=%q job=%q; want accepted/done", deliveryStatus, jobStatus)
	}
}

func TestWorkerRetriesQueuedEmailThenMarksFailed(t *testing.T) {
	database, svc := setup(t)
	queue := mailer.NewQueue(database)
	if err := queue.Send(context.Background(), mailer.Message{
		To: []string{"person@example.com"}, Subject: "Hello", Text: "Body",
		IdempotencyKey: "test/retry",
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := database.Exec(`UPDATE jobs SET max_attempts = 1, run_at = ? WHERE type = ?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339), mailer.EmailJobType); err != nil {
		t.Fatalf("prepare job: %v", err)
	}

	failing := &failingMailer{}
	w := worker.New(database, svc, slog.Default(), worker.WithMailer(failing),
		worker.WithHTTPClient(&http.Client{}))
	w.Poll(context.Background())

	var deliveryStatus, jobStatus string
	database.QueryRow(`SELECT status FROM email_deliveries LIMIT 1`).Scan(&deliveryStatus)            // #nosec G104 -- asserted below
	database.QueryRow(`SELECT status FROM jobs WHERE type = ?`, mailer.EmailJobType).Scan(&jobStatus) // #nosec G104 -- asserted below
	if failing.attempts != 1 || deliveryStatus != "failed" || jobStatus != "failed" {
		t.Fatalf("attempts=%d delivery=%q job=%q; want 1/failed/failed",
			failing.attempts, deliveryStatus, jobStatus)
	}
}
