package mailer

import (
	"context"
	"testing"

	appdb "github.com/calnode/calnode/internal/db"
)

func openQueueTestDB(t *testing.T) *Queue {
	t.Helper()
	database, err := appdb.Open("sqlite://" + t.TempDir() + "/queue.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() }) // #nosec G104 -- test cleanup
	if err := appdb.Migrate(database); err != nil {
		t.Fatalf("migrate db: %v", err)
	}
	return NewQueue(database)
}

func TestQueueSendPersistsDeliveryAndJobAtomically(t *testing.T) {
	queue := openQueueTestDB(t)
	msg := Message{
		To:             []string{"person@example.com"},
		Subject:        "Booking confirmed",
		Text:           "Your booking is confirmed.",
		IdempotencyKey: "booking/confirmed/booking-1/person@example.com",
	}
	if err := queue.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var deliveries, jobs int
	if err := queue.db.QueryRow(`SELECT COUNT(*) FROM email_deliveries`).Scan(&deliveries); err != nil {
		t.Fatalf("count deliveries: %v", err)
	}
	if err := queue.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE type = ?`, EmailJobType).Scan(&jobs); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if deliveries != 1 || jobs != 1 {
		t.Fatalf("deliveries=%d jobs=%d; want 1 and 1", deliveries, jobs)
	}
}

func TestQueueSendDeduplicatesSameLifecycleEvent(t *testing.T) {
	queue := openQueueTestDB(t)
	msg := Message{
		To:             []string{"person@example.com"},
		Subject:        "Booking confirmed",
		Text:           "Your booking is confirmed.",
		IdempotencyKey: "booking/confirmed/booking-1/person@example.com",
	}
	for range 2 {
		if err := queue.Send(context.Background(), msg); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	var deliveries, jobs int
	queue.db.QueryRow(`SELECT COUNT(*) FROM email_deliveries`).Scan(&deliveries)            // #nosec G104 -- asserted below
	queue.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE type = ?`, EmailJobType).Scan(&jobs) // #nosec G104 -- asserted below
	if deliveries != 1 || jobs != 1 {
		t.Fatalf("deliveries=%d jobs=%d; want deduplicated 1 and 1", deliveries, jobs)
	}
}
