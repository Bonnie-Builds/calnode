package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/calnode/calnode/internal/booking"
)

const managedBookingMaxBody = 64 << 10

type managedBookingParticipant struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type managedBookingUpsertRequest struct {
	EventTypeSlug    string                      `json:"event_type_slug"`
	BookingID        *string                     `json:"booking_id"`
	ExpectedRevision *string                     `json:"expected_revision"`
	StartAt          string                      `json:"start_at"`
	EndAt            string                      `json:"end_at"`
	Timezone         string                      `json:"timezone"`
	CorrelationRef   string                      `json:"correlation_ref"`
	Organizer        managedBookingParticipant   `json:"organizer"`
	Participants     []managedBookingParticipant `json:"participants"`
}

type managedBookingCancelRequest struct {
	ExpectedRevision string `json:"expected_revision"`
	Reason           string `json:"reason"`
}

type managedBookingLocationRequest struct {
	ExpectedRevision string `json:"expected_revision"`
	CorrelationRef   string `json:"correlation_ref"`
	LocationValue    string `json:"location_value"`
}

// ManagedBookingUpsert is the Bonnie-only deterministic direct-scheduling
// mutation. It is available only to a managed member API key, binds the stable
// event type and any existing booking to that exact member, requires an
// idempotency key, and revision-fences updates.
func (h *Handler) ManagedBookingUpsert(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireManagedBookingCaller(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, managedBookingMaxBody)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid booking request")
		return
	}
	var request managedBookingUpsertRequest
	if err := decodeStrictJSON(rawBody, &request); err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid booking request")
		return
	}

	idemKey, owned := h.claimManagedMutation(w, r, rawBody)
	if !owned {
		return
	}
	idemDone := false
	defer func() {
		if !idemDone {
			h.releaseIdempotencyKey(context.Background(), idemKey)
		}
	}()

	startAt, endAt, participants, valid := h.validateManagedBookingUpsert(w, request, user)
	if !valid {
		return
	}
	et, err := h.loadBookableEventType(r.Context(), request.EventTypeSlug)
	if err != nil || et.UserID != user.ID {
		h.writeCodedError(w, http.StatusNotFound, "event_type_not_found", "event type not found")
		return
	}
	if !endAt.Equal(startAt.Add(time.Duration(et.DurationMinutes) * time.Minute)) {
		h.writeCodedError(w, http.StatusUnprocessableEntity, "duration_mismatch", "booking duration does not match event type")
		return
	}

	var result *booking.Booking
	statusCode := http.StatusOK
	if request.BookingID == nil {
		if request.ExpectedRevision != nil {
			h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "new booking cannot include expected revision")
			return
		}
		result, err = h.createManagedBooking(r, et, request, startAt, endAt, participants)
		statusCode = http.StatusCreated
	} else {
		if request.ExpectedRevision == nil || strings.TrimSpace(*request.ExpectedRevision) == "" {
			h.writeCodedError(w, http.StatusBadRequest, "expected_revision_required", "expected revision is required")
			return
		}
		result, err = h.updateManagedBooking(r, et, request, startAt, endAt, participants, user.ID)
	}
	if err != nil {
		h.writeManagedBookingMutationError(w, r, err)
		return
	}

	response, err := json.Marshal(toBookingJSON(result))
	if err != nil {
		h.writeCodedError(w, http.StatusInternalServerError, "internal_error", "booking mutation failed")
		return
	}
	if err := h.finishIdempotencyKey(r.Context(), idemKey, statusCode, response, result.ID); err != nil {
		h.logger.ErrorContext(r.Context(), "managed booking upsert: store idempotency response", "error", err, "booking_id", result.ID)
	}
	idemDone = true
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(response)
}

func (h *Handler) createManagedBooking(r *http.Request, et *bookableEventType, request managedBookingUpsertRequest, startAt, endAt time.Time, participants []booking.Attendee) (*booking.Booking, error) {
	hosts, err := h.resolveEventTypeHosts(r.Context(), et.ID)
	if err != nil {
		return nil, err
	}
	candidates, required, optional := resolveBookingHostPool(hosts, et.RoutingMode)
	if len(candidates) == 0 {
		return nil, errNoHostAvailable
	}
	if err := h.validateBookingTime(r.Context(), et, et.RoutingMode, candidates, required, startAt, endAt); err != nil {
		return nil, err
	}
	location := ""
	if et.LocationValue != nil {
		location = *et.LocationValue
	}
	created, err := h.bookingSvc.Create(r.Context(), booking.CreateParams{
		EventTypeID: et.ID, HostIDs: candidates, RoutingMode: et.RoutingMode,
		RRStrategy: et.RRStrategy, RequiredHosts: required, OptionalHosts: optional,
		StartAt: startAt, EndAt: endAt, LocationValue: location,
		Organizer: participants[0], Participants: participants[1:],
		CorrelationRef: request.CorrelationRef, MaxActivePerInvitee: et.MaxActiveBookings,
	})
	if err != nil {
		return nil, err
	}
	go h.dispatchBookingConfirmation(created, bookingConfirmationInput{ // #nosec G118 -- existing durable side-effect boundary owns its background context
		EventTypeName: et.Name, EventTypeSlug: request.EventTypeSlug,
		LocationType: et.LocationType, OrganizerName: participants[0].Name,
		OrganizerEmail: participants[0].Email, OrganizerTimezone: participants[0].IANATimezone,
		Participants: participants[1:],
	})
	return created, nil
}

func (h *Handler) updateManagedBooking(r *http.Request, et *bookableEventType, request managedBookingUpsertRequest, startAt, endAt time.Time, participants []booking.Attendee, userID string) (*booking.Booking, error) {
	id := strings.TrimSpace(*request.BookingID)
	var hostID, eventTypeID, currentRevision, correlation, status string
	err := h.db.QueryRowContext(r.Context(), `
		SELECT host_id, event_type_id, updated_at, COALESCE(correlation_ref,''), status
		FROM bookings WHERE id = ?`, id).
		Scan(&hostID, &eventTypeID, &currentRevision, &correlation, &status)
	if err != nil || hostID != userID || eventTypeID != et.ID {
		return nil, booking.ErrNotFound
	}
	if status == "cancelled" {
		return nil, booking.ErrAlreadyCancelled
	}
	if currentRevision != strings.TrimSpace(*request.ExpectedRevision) {
		return nil, errManagedRevisionConflict
	}
	if correlation != request.CorrelationRef {
		return nil, errManagedCorrelationConflict
	}
	matches, err := h.managedParticipantsMatch(r, id, participants)
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, errManagedParticipantsConflict
	}
	if err := h.validateRescheduleTime(r.Context(), id, et.ID, userID, startAt, endAt); err != nil {
		return nil, err
	}
	current, err := h.bookingSvc.Get(r.Context(), id)
	if err != nil {
		return nil, err
	}
	updated, err := h.bookingSvc.RescheduleWithTimezone(r.Context(), id, startAt, endAt, request.Timezone)
	if err != nil {
		return nil, err
	}
	go h.rescheduleSideEffects(*updated, et.ID, current.StartAt, current.EndAt) // #nosec G118 -- existing durable side-effect boundary owns its background context
	return updated, nil
}

// ManagedBookingLocation revision-fences a Bonnie Room invitation attachment
// to the exact managed member booking. External calendar events are patched
// first; only then is the provider booking revision advanced, so a subsequent
// authenticated GET is authoritative for convergence.
func (h *Handler) ManagedBookingLocation(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireManagedBookingCaller(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, managedBookingMaxBody)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid booking location request")
		return
	}
	var request managedBookingLocationRequest
	if err := decodeStrictJSON(rawBody, &request); err != nil || !validManagedBookingLocation(request.LocationValue) || !validCorrelationRef(request.CorrelationRef) || strings.TrimSpace(request.ExpectedRevision) == "" {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid booking location request")
		return
	}
	idemKey, owned := h.claimManagedMutation(w, r, rawBody)
	if !owned {
		return
	}
	idemDone := false
	defer func() {
		if !idemDone {
			h.releaseIdempotencyKey(context.Background(), idemKey)
		}
	}()
	id := strings.TrimSpace(r.PathValue("id"))
	var hostID, revision, correlation, status string
	if err := h.db.QueryRowContext(r.Context(), `
		SELECT host_id, updated_at, COALESCE(correlation_ref,''), status
		FROM bookings WHERE id = ?`, id).Scan(&hostID, &revision, &correlation, &status); err != nil || hostID != user.ID {
		h.writeCodedError(w, http.StatusNotFound, "booking_not_found", "booking not found")
		return
	}
	if status == "cancelled" {
		h.writeCodedError(w, http.StatusConflict, "booking_cancelled", "booking is cancelled")
		return
	}
	if revision != strings.TrimSpace(request.ExpectedRevision) {
		h.writeCodedError(w, http.StatusConflict, "revision_conflict", "booking revision conflict")
		return
	}
	if correlation != strings.TrimSpace(request.CorrelationRef) {
		h.writeCodedError(w, http.StatusConflict, "correlation_conflict", "booking correlation conflict")
		return
	}
	location := strings.TrimSpace(request.LocationValue)
	if err := h.updateManagedCalendarLocations(r.Context(), id, location); err != nil {
		h.logger.ErrorContext(r.Context(), "managed booking location: update calendar", "error", err, "booking_id", id)
		h.writeCodedError(w, http.StatusServiceUnavailable, "calendar_update_failed", "booking location update failed")
		return
	}
	updated, err := h.bookingSvc.UpdateLocation(r.Context(), id, location)
	if err != nil {
		h.writeManagedBookingMutationError(w, r, err)
		return
	}
	response, err := json.Marshal(toBookingJSON(updated))
	if err != nil {
		h.writeCodedError(w, http.StatusInternalServerError, "internal_error", "booking location update failed")
		return
	}
	if err := h.finishIdempotencyKey(r.Context(), idemKey, http.StatusOK, response, id); err != nil {
		h.logger.ErrorContext(r.Context(), "managed booking location: store idempotency response", "error", err, "booking_id", id)
	}
	idemDone = true
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func validManagedBookingLocation(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/meetings/rooms/") {
		return false
	}
	return parsed.Scheme == "https" || (parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"))
}

func (h *Handler) updateManagedCalendarLocations(ctx context.Context, bookingID, location string) error {
	calendarService := h.getCal()
	if calendarService == nil {
		return errors.New("calendar service unavailable")
	}
	hosts, err := h.assignedHosts(ctx, bookingID)
	if err != nil {
		return err
	}
	updated := 0
	for _, host := range hosts {
		if host.ExternalEventID == "" {
			continue
		}
		if err := calendarService.UpdateEventLocation(ctx, host.UserID, host.ExternalEventID, location); err != nil {
			return err
		}
		updated++
	}
	if updated == 0 {
		return errors.New("booking calendar event unavailable")
	}
	return nil
}

// ManagedBookingCancel revision-fences and idempotently cancels only the exact
// managed member's booking. A replay returns the stored normalized response.
func (h *Handler) ManagedBookingCancel(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireManagedBookingCaller(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, managedBookingMaxBody)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "invalid cancel request")
		return
	}
	var request managedBookingCancelRequest
	if err := decodeStrictJSON(rawBody, &request); err != nil || strings.TrimSpace(request.ExpectedRevision) == "" || strings.TrimSpace(request.Reason) == "" {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "expected revision and reason are required")
		return
	}
	idemKey, owned := h.claimManagedMutation(w, r, rawBody)
	if !owned {
		return
	}
	idemDone := false
	defer func() {
		if !idemDone {
			h.releaseIdempotencyKey(context.Background(), idemKey)
		}
	}()
	id := r.PathValue("id")
	var hostID, revision string
	if err := h.db.QueryRowContext(r.Context(), `SELECT host_id, updated_at FROM bookings WHERE id = ?`, id).Scan(&hostID, &revision); err != nil || hostID != user.ID {
		h.writeCodedError(w, http.StatusNotFound, "booking_not_found", "booking not found")
		return
	}
	if revision != strings.TrimSpace(request.ExpectedRevision) {
		h.writeCodedError(w, http.StatusConflict, "revision_conflict", "booking revision conflict")
		return
	}
	if err := h.bookingSvc.Cancel(r.Context(), user.ID, id, request.Reason); err != nil {
		h.writeManagedBookingMutationError(w, r, err)
		return
	}
	cancelled, err := h.bookingSvc.Get(r.Context(), id)
	if err != nil {
		h.writeManagedBookingMutationError(w, r, err)
		return
	}
	response, err := json.Marshal(toBookingJSON(cancelled))
	if err != nil {
		h.writeCodedError(w, http.StatusInternalServerError, "internal_error", "booking mutation failed")
		return
	}
	if err := h.finishIdempotencyKey(r.Context(), idemKey, http.StatusOK, response, id); err != nil {
		h.logger.ErrorContext(r.Context(), "managed booking cancel: store idempotency response", "error", err, "booking_id", id)
	}
	idemDone = true
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
	go h.cancelSideEffects(*cancelled) // #nosec G118 -- existing durable side-effect boundary owns its background context
}

func (h *Handler) requireManagedBookingCaller(w http.ResponseWriter, r *http.Request) (AuthUser, bool) {
	if !h.bonnieManagedMode {
		h.writeCodedError(w, http.StatusNotFound, "not_found", "not found")
		return AuthUser{}, false
	}
	user, ok := userFromContext(r.Context())
	if !ok || !user.IsManagedMember || user.IsAdmin || user.IsOwner || extractAPIKey(r) == "" {
		h.writeCodedError(w, http.StatusForbidden, "managed_member_required", "managed member API key required")
		return AuthUser{}, false
	}
	return user, true
}

func (h *Handler) claimManagedMutation(w http.ResponseWriter, r *http.Request, rawBody []byte) (string, bool) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 255 {
		h.writeCodedError(w, http.StatusBadRequest, "idempotency_key_required", "valid Idempotency-Key required")
		return "", false
	}
	record, replay, err := h.claimIdempotencyKey(r.Context(), key, idemHash(rawBody))
	if err != nil {
		h.writeCodedError(w, http.StatusInternalServerError, "internal_error", "booking mutation failed")
		return "", false
	}
	if !replay {
		return key, true
	}
	if record.StatusCode == 0 {
		h.writeCodedError(w, http.StatusConflict, "operation_in_progress", "operation is still being processed")
		return "", false
	}
	if record.RequestHash != idemHash(rawBody) {
		h.writeCodedError(w, http.StatusUnprocessableEntity, "idempotency_conflict", "Idempotency-Key was already used with a different request")
		return "", false
	}
	w.Header().Set("Idempotency-Replayed", "true")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(record.StatusCode)
	_, _ = w.Write([]byte(record.ResponseBody))
	return "", false
}

func (h *Handler) validateManagedBookingUpsert(w http.ResponseWriter, request managedBookingUpsertRequest, user AuthUser) (time.Time, time.Time, []booking.Attendee, bool) {
	if strings.TrimSpace(request.EventTypeSlug) == "" || strings.TrimSpace(request.StartAt) == "" || strings.TrimSpace(request.EndAt) == "" || strings.TrimSpace(request.Timezone) == "" || !validCorrelationRef(strings.TrimSpace(request.CorrelationRef)) {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "required booking fields are invalid")
		return time.Time{}, time.Time{}, nil, false
	}
	if !strings.EqualFold(strings.TrimSpace(request.Organizer.Email), user.Email) || strings.TrimSpace(request.Organizer.Name) == "" {
		h.writeCodedError(w, http.StatusForbidden, "organizer_mismatch", "organizer does not match managed member")
		return time.Time{}, time.Time{}, nil, false
	}
	if _, err := time.LoadLocation(strings.TrimSpace(request.Timezone)); err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_timezone", "booking timezone is invalid")
		return time.Time{}, time.Time{}, nil, false
	}
	if len(request.Participants) == 0 || len(request.Participants) > 64 {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_participants", "between one and 64 participants are required")
		return time.Time{}, time.Time{}, nil, false
	}
	organizerEmail := strings.ToLower(strings.TrimSpace(request.Organizer.Email))
	participants := make([]booking.Attendee, 0, len(request.Participants)+1)
	participants = append(participants, booking.Attendee{Name: strings.TrimSpace(request.Organizer.Name), Email: organizerEmail, IANATimezone: request.Timezone})
	seen := map[string]struct{}{organizerEmail: {}}
	for _, item := range request.Participants {
		name := strings.TrimSpace(item.Name)
		email := strings.ToLower(strings.TrimSpace(item.Email))
		parsed, err := mail.ParseAddress(email)
		if name == "" || err != nil || parsed.Address != email {
			h.writeCodedError(w, http.StatusBadRequest, "invalid_participants", "participant identity is invalid")
			return time.Time{}, time.Time{}, nil, false
		}
		if _, duplicate := seen[email]; duplicate {
			h.writeCodedError(w, http.StatusBadRequest, "invalid_participants", "participant identities must be distinct")
			return time.Time{}, time.Time{}, nil, false
		}
		seen[email] = struct{}{}
		participants = append(participants, booking.Attendee{Name: name, Email: email, IANATimezone: request.Timezone})
	}
	startAt, err := time.Parse(time.RFC3339, request.StartAt)
	if err != nil {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_time", "booking time is invalid")
		return time.Time{}, time.Time{}, nil, false
	}
	endAt, err := time.Parse(time.RFC3339, request.EndAt)
	if err != nil || !endAt.After(startAt) {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_time", "booking time is invalid")
		return time.Time{}, time.Time{}, nil, false
	}
	return startAt.UTC(), endAt.UTC(), participants, true
}

func (h *Handler) managedParticipantsMatch(r *http.Request, bookingID string, expected []booking.Attendee) (bool, error) {
	rows, err := h.db.QueryContext(r.Context(), `SELECT email FROM booking_attendees WHERE booking_id = ? ORDER BY is_organizer DESC, id`, bookingID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	actual := make([]string, 0, len(expected))
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return false, err
		}
		actual = append(actual, strings.ToLower(email))
	}
	if err := rows.Err(); err != nil || len(actual) != len(expected) {
		return false, err
	}
	for index := range actual {
		if actual[index] != strings.ToLower(expected[index].Email) {
			return false, nil
		}
	}
	return true, nil
}

func (h *Handler) writeManagedBookingMutationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, booking.ErrNotFound):
		h.writeCodedError(w, http.StatusNotFound, "booking_not_found", "booking not found")
	case errors.Is(err, booking.ErrAlreadyCancelled):
		h.writeCodedError(w, http.StatusConflict, "booking_cancelled", "booking is cancelled")
	case errors.Is(err, booking.ErrDoubleBooked), errors.Is(err, errSlotUnavailable), errors.Is(err, errNoHostAvailable):
		h.writeCodedError(w, http.StatusConflict, "slot_unavailable", "booking slot is unavailable")
	case errors.Is(err, errManagedRevisionConflict):
		h.writeCodedError(w, http.StatusConflict, "revision_conflict", "booking revision conflict")
	case errors.Is(err, errManagedCorrelationConflict):
		h.writeCodedError(w, http.StatusConflict, "correlation_conflict", "booking correlation conflict")
	case errors.Is(err, errManagedParticipantsConflict):
		h.writeCodedError(w, http.StatusConflict, "participants_conflict", "booking participants conflict")
	default:
		h.logger.ErrorContext(r.Context(), "managed booking mutation failed", "error", err)
		h.writeCodedError(w, http.StatusInternalServerError, "internal_error", "booking mutation failed")
	}
}

var (
	errManagedRevisionConflict     = errors.New("managed booking revision conflict")
	errManagedCorrelationConflict  = errors.New("managed booking correlation conflict")
	errManagedParticipantsConflict = errors.New("managed booking participants conflict")
)
