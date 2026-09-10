package handler

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/calnode/calnode/internal/booking"
	"github.com/calnode/calnode/internal/calendar"
)

// A Bonnie correlation marks a booking owned by the Meeting workflow. The
// configured bot identity is never accepted from the public booking payload.
func (h *Handler) correlatedMeetingGuests(locationType, correlationRef, organizerEmail string) ([]booking.Attendee, error) {
	if !h.bonnieManagedMode || correlationRef == "" || locationType != "google_meet" {
		return nil, nil
	}
	email := h.bonnieMeetingBotEmail
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || address.Name != "" {
		return nil, errors.New("managed meeting guest is not configured")
	}
	if strings.EqualFold(strings.TrimSpace(organizerEmail), email) {
		return nil, nil
	}
	return []booking.Attendee{{Name: "Bonnie", Email: email, IANATimezone: "UTC"}}, nil
}

// Calendar creation and repair read the same persisted participant set, including
// managed direct-booking guests and correlated availability-link guests.
func (h *Handler) calendarBookingParticipants(ctx context.Context, bookingID string) ([]calendar.EventAttendee, error) {
	rows, err := h.db.QueryContext(ctx, `SELECT name, email FROM booking_attendees WHERE booking_id = ? AND is_organizer = 0 ORDER BY id`, bookingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	participants := make([]calendar.EventAttendee, 0)
	for rows.Next() {
		var participant calendar.EventAttendee
		if err := rows.Scan(&participant.Name, &participant.Email); err != nil {
			return nil, err
		}
		participants = append(participants, participant)
	}
	return participants, rows.Err()
}
