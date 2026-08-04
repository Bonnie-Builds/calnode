package mailer

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/calnode/calnode/internal/uid"
)

const EmailJobType = "email.send"

type queuedEmailPayload struct {
	DeliveryID string `json:"delivery_id"`
}

// Queue is a durable Mailer. Send commits the immutable message and its worker
// job in one transaction; network delivery happens asynchronously in Worker.
type Queue struct {
	db *sql.DB
}

func NewQueue(db *sql.DB) *Queue {
	return &Queue{db: db}
}

func (q *Queue) Send(ctx context.Context, msg Message) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("mailer: enqueue: at least one recipient is required")
	}
	messageJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("mailer: enqueue: encode message: %w", err)
	}
	idempotencyKey := msg.IdempotencyKey
	if idempotencyKey == "" {
		sum := sha256.Sum256(messageJSON)
		idempotencyKey = "message/" + hex.EncodeToString(sum[:])
	}

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mailer: enqueue: begin: %w", err)
	}
	defer tx.Rollback() // #nosec G104 -- commit/operation errors are returned below

	deliveryID := uid.New()
	result, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO email_deliveries
		  (id, idempotency_key, recipient, subject, message_json, status)
		VALUES (?, ?, ?, ?, ?, 'pending')`,
		deliveryID, idempotencyKey, strings.Join(msg.To, ", "), msg.Subject, string(messageJSON))
	if err != nil {
		return fmt.Errorf("mailer: enqueue: insert delivery: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("mailer: enqueue: rows affected: %w", err)
	}
	if inserted == 0 {
		if err := tx.QueryRowContext(ctx,
			`SELECT id FROM email_deliveries WHERE idempotency_key = ?`, idempotencyKey).
			Scan(&deliveryID); err != nil {
			return fmt.Errorf("mailer: enqueue: load existing delivery: %w", err)
		}
	}

	payload, err := json.Marshal(queuedEmailPayload{DeliveryID: deliveryID})
	if err != nil {
		return fmt.Errorf("mailer: enqueue: encode job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO jobs (id, type, payload, run_at, status, attempts, max_attempts)
		VALUES (?, ?, ?, ?, 'pending', 0, 3)`,
		uid.New(), EmailJobType, string(payload), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("mailer: enqueue: insert job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("mailer: enqueue: commit: %w", err)
	}
	return nil
}

func DecodeQueuedEmailPayload(payload string) (string, error) {
	var parsed queuedEmailPayload
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		return "", fmt.Errorf("mailer: queued payload: %w", err)
	}
	if parsed.DeliveryID == "" {
		return "", fmt.Errorf("mailer: queued payload: delivery_id is required")
	}
	return parsed.DeliveryID, nil
}
