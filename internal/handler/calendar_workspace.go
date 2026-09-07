package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/calnode/calnode/internal/booking"
	"github.com/calnode/calnode/internal/slots"
)

const (
	managedCalendarMaxRange       = 42 * 24 * time.Hour
	managedCalendarDefaultPage    = 100
	managedCalendarMaxPage        = 100
	managedCalendarMaxDensity     = 200
	managedCalendarMaxBusyPeriods = 200
)

type managedCalendarBookingJSON struct {
	BookingRef     string `json:"booking_ref"`
	Title          string `json:"title"`
	StartsAt       string `json:"starts_at"`
	EndsAt         string `json:"ends_at"`
	TimeZone       string `json:"time_zone"`
	CorrelationRef string `json:"correlation_ref,omitempty"`
}

type managedCalendarBusyJSON struct {
	StartsAt string `json:"starts_at"`
	EndsAt   string `json:"ends_at"`
}

type managedCalendarPageJSON struct {
	Limit      int     `json:"limit"`
	HasMore    bool    `json:"has_more"`
	NextCursor *string `json:"next_cursor"`
}

type managedCalendarRangeJSON struct {
	SchemaVersion int                          `json:"schema_version"`
	RangeStart    string                       `json:"range_start"`
	RangeEnd      string                       `json:"range_end"`
	TimeZone      string                       `json:"time_zone"`
	ProviderState string                       `json:"provider_state"`
	Bookings      []managedCalendarBookingJSON `json:"bookings"`
	Busy          []managedCalendarBusyJSON    `json:"busy"`
	Page          managedCalendarPageJSON      `json:"page"`
}

type managedCalendarRangeRequest struct {
	Assertion string `json:"assertion"`
	From      string `json:"from"`
	To        string `json:"to"`
	TimeZone  string `json:"time_zone"`
	Limit     int    `json:"limit"`
	Cursor    string `json:"cursor,omitempty"`
}

type managedCalendarCursor struct {
	start time.Time
	id    string
}

func parseManagedCalendarInstant(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func parseManagedCalendarLimit(value int) (int, bool) {
	if value == 0 {
		return managedCalendarDefaultPage, true
	}
	if value < 1 || value > managedCalendarMaxPage {
		return 0, false
	}
	return value, true
}

func encodeManagedCalendarCursor(item booking.CalendarBooking) string {
	payload := item.StartAt.UTC().Format(time.RFC3339Nano) + "\x00" + item.ID
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeManagedCalendarCursor(value string) (managedCalendarCursor, bool) {
	if value == "" {
		return managedCalendarCursor{}, true
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > 1024 {
		return managedCalendarCursor{}, false
	}
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) != 2 || parts[1] == "" || len(parts[1]) > 512 {
		return managedCalendarCursor{}, false
	}
	start, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return managedCalendarCursor{}, false
	}
	return managedCalendarCursor{start: start.UTC(), id: parts[1]}, true
}

func bookingAfterManagedCalendarCursor(item booking.CalendarBooking, cursor managedCalendarCursor) bool {
	if cursor.id == "" {
		return true
	}
	if item.StartAt.After(cursor.start) {
		return true
	}
	return item.StartAt.Equal(cursor.start) && item.ID > cursor.id
}

func boundedCalendarTitle(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Meeting"
	}
	runes := []rune(value)
	if len(runes) > 160 {
		return string(runes[:160])
	}
	return value
}

func decodeManagedCalendarRangeRequest(w http.ResponseWriter, r *http.Request) (*managedCalendarRangeRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, managedAssertionMaxBody+4<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request managedCalendarRangeRequest
	if err := decoder.Decode(&request); err != nil {
		return nil, false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err == nil {
		return nil, false
	}
	return &request, true
}

// ManagedCalendarRange is the exact-member, bounded, privacy-minimal calendar
// boundary used by Bonnie's Meetings capability worker. A fresh Bonnie-managed
// assertion selects the company and subject; the body never accepts a member,
// company, provider, role, provider URL, or credential selector.
func (h *Handler) ManagedCalendarRange(w http.ResponseWriter, r *http.Request) {
	if !h.bonnieManagedMode {
		h.writeCodedError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	request, requestOK := decodeManagedCalendarRangeRequest(w, r)
	if !requestOK || request == nil || request.Assertion == "" {
		h.writeCodedError(w, http.StatusBadRequest, "invalid_request", "calendar request is invalid")
		return
	}
	claims, err := h.verifyManagedAssertion(r.Context(), request.Assertion)
	if err != nil {
		h.logger.WarnContext(r.Context(), "managed calendar range rejected", "reason", err.Error())
		h.writeCodedError(w, http.StatusUnauthorized, "managed_assertion_rejected", "assertion rejected")
		return
	}
	consumed, err := h.consumeJTI(r.Context(), claims.JTI)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "managed calendar range assertion consume", "error", err)
		h.writeCodedError(w, http.StatusServiceUnavailable, "calendar_read_unavailable", "calendar is unavailable")
		return
	}
	if !consumed {
		h.writeCodedError(w, http.StatusUnauthorized, "managed_assertion_rejected", "assertion rejected")
		return
	}
	userID, found := h.getActiveManagedMemberBySub(r.Context(), claims.Sub)
	if !found {
		h.writeCodedError(w, http.StatusForbidden, "managed_member_required", "managed member required")
		return
	}

	from, fromOK := parseManagedCalendarInstant(request.From)
	to, toOK := parseManagedCalendarInstant(request.To)
	limit, limitOK := parseManagedCalendarLimit(request.Limit)
	cursor, cursorOK := decodeManagedCalendarCursor(request.Cursor)
	timeZone := strings.TrimSpace(request.TimeZone)
	_, zoneErr := time.LoadLocation(timeZone)
	if !fromOK || !toOK || !limitOK || !cursorOK || zoneErr != nil || !to.After(from) || to.Sub(from) > managedCalendarMaxRange {
		h.writeCodedError(w, http.StatusUnprocessableEntity, "invalid_calendar_range", "calendar range is invalid")
		return
	}

	allBookings, err := h.bookingSvc.ListCalendarByHostRange(
		r.Context(), userID, from, to, managedCalendarMaxDensity,
	)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "managed calendar range bookings", "error", err)
		h.writeCodedError(w, http.StatusServiceUnavailable, "calendar_read_unavailable", "calendar is unavailable")
		return
	}
	if len(allBookings) > managedCalendarMaxDensity {
		h.writeCodedError(w, http.StatusUnprocessableEntity, "calendar_range_too_dense", "calendar range is too dense")
		return
	}

	pageCandidates := make([]booking.CalendarBooking, 0, len(allBookings))
	for _, item := range allBookings {
		if bookingAfterManagedCalendarCursor(item, cursor) {
			pageCandidates = append(pageCandidates, item)
		}
	}
	hasMore := len(pageCandidates) > limit
	if hasMore {
		pageCandidates = pageCandidates[:limit]
	}

	bookings := make([]managedCalendarBookingJSON, 0, len(pageCandidates))
	for _, item := range pageCandidates {
		bookings = append(bookings, managedCalendarBookingJSON{
			BookingRef:     item.ID,
			Title:          boundedCalendarTitle(item.Title),
			StartsAt:       item.StartAt.UTC().Format(time.RFC3339),
			EndsAt:         item.EndAt.UTC().Format(time.RFC3339),
			TimeZone:       item.Timezone,
			CorrelationRef: item.CorrelationRef,
		})
	}

	providerState := "unavailable"
	busy := make([]managedCalendarBusyJSON, 0)
	if cal := h.getCal(); cal != nil {
		providerBusy, freeBusyErr := cal.FreeBusy(r.Context(), userID, from, to)
		connected, connectionErr := cal.HasDestination(r.Context(), userID)
		switch {
		case freeBusyErr != nil || connectionErr != nil:
			providerState = "retryable_failure"
		case !connected:
			providerState = "action_required"
		default:
			cuts := make([]slots.Interval, 0, len(allBookings))
			for _, item := range allBookings {
				cuts = append(cuts, slots.Interval{Start: item.StartAt, End: item.EndAt})
			}
			providerBusy = slots.SubtractIntervals(providerBusy, cuts)
			if len(providerBusy) > managedCalendarMaxBusyPeriods {
				h.writeCodedError(w, http.StatusUnprocessableEntity, "calendar_range_too_dense", "calendar range is too dense")
				return
			}
			providerState = "ready"
			for _, interval := range providerBusy {
				start := interval.Start.UTC()
				end := interval.End.UTC()
				if start.Before(from) {
					start = from
				}
				if end.After(to) {
					end = to
				}
				if end.After(start) {
					busy = append(busy, managedCalendarBusyJSON{
						StartsAt: start.Format(time.RFC3339),
						EndsAt:   end.Format(time.RFC3339),
					})
				}
			}
		}
	}

	var nextCursor *string
	if hasMore && len(pageCandidates) > 0 {
		encoded := encodeManagedCalendarCursor(pageCandidates[len(pageCandidates)-1])
		nextCursor = &encoded
	}
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	h.writeJSON(w, http.StatusOK, managedCalendarRangeJSON{
		SchemaVersion: 1,
		RangeStart:    from.Format(time.RFC3339),
		RangeEnd:      to.Format(time.RFC3339),
		TimeZone:      timeZone,
		ProviderState: providerState,
		Bookings:      bookings,
		Busy:          busy,
		Page:          managedCalendarPageJSON{Limit: limit, HasMore: hasMore, NextCursor: nextCursor},
	})
}
