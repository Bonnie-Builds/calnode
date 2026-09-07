package gcal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/calnode/calnode/internal/calendar"
	"github.com/calnode/calnode/internal/custody"
	"github.com/calnode/calnode/internal/slots"
)

// Custody transport adapter (Phase 3, Orchestrator Fork Adapter Contract):
// routes the four allowlisted Google effects through Bonbon's operation-shaped
// custody boundary. Remote-transport-only — calls and response mapping.
//
// Authority split is unchanged: slot computation/policy, booking state,
// correlation semantics, rendering, and transactional mail stay in Calnode.
// There are no credential fields, no credential-descriptor kind field, and no
// kind branches here: the adapter neither knows nor selects credential kinds.
//
// When no custody transport is configured (default) every effect keeps its
// existing direct-Google path unchanged.

var (
	// ErrCustodyPending marks an unresolved effect: ambiguous at the boundary
	// or read-back not yet conclusive. It is transient-safe — never a readiness
	// flip, never a re-issue of the effect. Callers keep their existing
	// reconciler/nudge behavior; retries ride read-back paths only.
	ErrCustodyPending = errors.New("gcal: custody effect unresolved; converge via event read-back")
	// ErrCustodyAuth wraps terminal custody refusals that are not user-fixable
	// reconnect states (wrong account/member, scope, operator-facing faults).
	ErrCustodyAuth = errors.New("gcal: custody refusal")
)

// errCustodyNoConnection lets mapCustodyOutcome signal refused(missing) so each
// effect translates it into its historical no-connection return shape.
var errCustodyNoConnection = errors.New("gcal: no usable custody connection")

func isNoConn(err error) bool { return errors.Is(err, errCustodyNoConnection) }

// EffectTransport executes one allowlisted custody request against Bonbon.
// *custody.Client satisfies it.
type EffectTransport interface {
	Execute(ctx context.Context, req custody.Request) (custody.Outcome, error)
}

// WithCustodyTransport configures the client to route Google effects through
// Bonbon's custody transport instead of direct Google API calls. companyRef /
// instanceRef are this deployment's tenant pins (server-side matched again by
// Bonbon).
func WithCustodyTransport(tx EffectTransport, companyRef, instanceRef string) Option {
	return func(c *Client) {
		c.custodyTx = tx
		c.custodyCompanyRef = strings.TrimSpace(companyRef)
		c.custodyInstanceRef = strings.TrimSpace(instanceRef)
	}
}

func (c *Client) custodyEnabled() bool { return c != nil && c.custodyTx != nil }

func (c *Client) custodyExecute(ctx context.Context, op custody.Operation, memberSub, stableOperationID string, payload map[string]any) (custody.Outcome, error) {
	req := custody.Request{
		Operation:         op,
		CompanyRef:        c.custodyCompanyRef,
		InstanceRef:       c.custodyInstanceRef,
		MemberSub:         memberSub,
		StableOperationID: stableOperationID,
		Payload:           payload,
	}
	return c.custodyTx.Execute(ctx, req)
}

// mapCustodyOutcome converts a non-ambiguous outcome into Calnode scheduling
// semantics without exposing provider detail:
//   - refused(missing) behaves exactly like direct-mode "no usable connection";
//   - revoked/expired surface the user-driven reconnect remedy;
//   - other terminal refusals surface as typed ErrCustodyAuth;
//   - unavailable/provider_unavailable surface as transient ErrCustodyPending.
func (c *Client) mapCustodyOutcome(outcome custody.Outcome) error {
	switch outcome.Kind {
	case custody.OutcomeAccepted, custody.OutcomeReplayed:
		return nil
	case custody.OutcomeAmbiguous:
		return fmt.Errorf("%w", ErrCustodyPending)
	case custody.OutcomeRefused:
		switch outcome.RefusalState {
		case custody.StateMissing:
			return errCustodyNoConnection
		case custody.StateRevoked, custody.StateExpired:
			return calendar.ErrReauthRequired
		default:
			return fmt.Errorf("%w: %s", ErrCustodyAuth, outcome.RefusalState)
		}
	default:
		return fmt.Errorf("%w (%s)", ErrCustodyPending, outcome.ProviderErrorClass)
	}
}

// destinationMemberSub resolves the managed member email. In custody mode
// Calnode has no provider connection row and never stores Google tokens.
func (c *Client) destinationMemberSub(ctx context.Context, userID string) (string, bool) {
	var email string
	err := c.db.QueryRowContext(ctx,
		`SELECT COALESCE(email,'') FROM users WHERE id = ? AND archived_at IS NULL LIMIT 1`, userID).Scan(&email)
	if err != nil || strings.TrimSpace(email) == "" {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			c.logger.Warn("custody: resolve destination member", "user_id", userID, "error", err)
		}
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(email)), true
}

// custodyEventID derives the deterministic provider event ID for one logical
// upsert. Determinism is what makes reconcile heals and retries converge on the
// same event instead of duplicating it.
func custodyEventID(stableKey string) string {
	var b strings.Builder
	for _, r := range stableKey {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteByte('-')
		}
	}
	sanitized := b.String()
	for strings.Contains(sanitized, "--") {
		sanitized = strings.ReplaceAll(sanitized, "--", "-")
	}
	sanitized = strings.Trim(sanitized, "-_")
	id := "cn-" + sanitized
	if len(id) > 60 {
		sum := sha256.Sum256([]byte(stableKey))
		id = "cn-" + sanitized[:36] + "-" + hex.EncodeToString(sum[:])[:16]
	}
	return id
}

func jsonMap(v any) map[string]any {
	out := map[string]any{}
	b, err := json.Marshal(v)
	if err != nil {
		return out
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]any{}
	}
	return out
}

type custodyEvent struct {
	ID             string `json:"id"`
	HangoutLink    string `json:"hangoutLink"`
	ConferenceData *struct {
		EntryPoints []struct {
			EntryPointType string `json:"entryPointType"`
			URI            string `json:"uri"`
		} `json:"entryPoints"`
	} `json:"conferenceData"`
	raw json.RawMessage
}

func (e custodyEvent) meetLink() string {
	if e.HangoutLink != "" {
		return e.HangoutLink
	}
	if e.ConferenceData != nil {
		for _, ep := range e.ConferenceData.EntryPoints {
			if ep.EntryPointType == "video" && ep.URI != "" {
				return ep.URI
			}
		}
	}
	return ""
}

func decodeCustodyEvent(result json.RawMessage) (custodyEvent, error) {
	var ev custodyEvent
	if len(result) == 0 || json.Unmarshal(result, &ev) != nil || strings.TrimSpace(ev.ID) == "" {
		return custodyEvent{}, fmt.Errorf("%w: event result missing identity", ErrCustodyPending)
	}
	ev.raw = result
	return ev, nil
}

// ---------------------------------------------------------------------------
// Effect bodies (mirrors the direct-path construction).
// ---------------------------------------------------------------------------

type custodyDateTime struct {
	DateTime string `json:"dateTime"`
	TimeZone string `json:"timeZone"`
}

type custodyAttendee struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName,omitempty"`
}

func buildCalEventReq(p calendar.CreateEventParams) map[string]any {
	attendees := []custodyAttendee{}
	if p.OrganizerEmail != "" {
		attendees = append(attendees, custodyAttendee{Email: p.OrganizerEmail, DisplayName: p.OrganizerName})
	}
	for _, a := range p.Attendees {
		attendees = append(attendees, custodyAttendee{Email: a.Email, DisplayName: a.Name})
	}
	body := map[string]any{
		"summary":   p.Summary,
		"start":     custodyDateTime{DateTime: p.Start.UTC().Format(time.RFC3339), TimeZone: "UTC"},
		"end":       custodyDateTime{DateTime: p.End.UTC().Format(time.RFC3339), TimeZone: "UTC"},
		"attendees": attendees,
	}
	if p.Description != "" {
		body["description"] = p.Description
	}
	if p.Location != "" {
		body["location"] = p.Location
	}
	if p.AddMeet {
		body["conferenceData"] = map[string]any{
			"createRequest": map[string]any{
				"requestId":             custodyEventID(p.StableOperationKey),
				"conferenceSolutionKey": map[string]any{"type": "hangoutsMeet"},
			},
		}
	}
	return body
}

// ---------------------------------------------------------------------------
// Effect routing with read-after-ambiguous convergence.
// ---------------------------------------------------------------------------

// custodyUpsertEventBody issues the upsert for one deterministic event body and,
// on ambiguity, converges via event_get using the SAME stable identity and
// deterministic eventId — never by re-issuing the effect call.
func (c *Client) custodyUpsertEventBody(ctx context.Context, memberSub, stableOperationID string, body map[string]any, eventID string) (custodyEvent, error) {
	payload := jsonMap(body)
	payload["calendarId"] = "primary"
	payload["eventId"] = eventID
	outcome, err := c.custodyExecute(ctx, custody.OperationEventUpsert, memberSub, stableOperationID, payload)
	if err != nil {
		return custodyEvent{}, err
	}
	if outcome.Kind == custody.OutcomeAmbiguous {
		c.logger.Warn("custody: upsert ambiguous; converging via event_get read-back",
			"stable_operation_id", stableOperationID, "event_id", eventID)
		return c.custodyReadBackAfterAmbiguity(ctx, memberSub, stableOperationID, eventID)
	}
	if err := c.mapCustodyOutcome(outcome); err != nil {
		return custodyEvent{}, err
	}
	return decodeCustodyEvent(outcome.Result)
}

// custodyReadBackAfterAmbiguity performs ONLY read calls after an ambiguous
// effect. If the read itself cannot conclude, the caller receives
// ErrCustodyPending and its existing reconciler retry behavior applies.
func (c *Client) custodyReadBackAfterAmbiguity(ctx context.Context, memberSub, stableOperationID, eventID string) (custodyEvent, error) {
	payload := map[string]any{"calendarId": "primary", "eventId": eventID}
	outcome, err := c.custodyExecute(ctx, custody.OperationEventGet, memberSub, stableOperationID, payload)
	if err != nil {
		return custodyEvent{}, err
	}
	switch outcome.Kind {
	case custody.OutcomeAccepted, custody.OutcomeReplayed:
		return decodeCustodyEvent(outcome.Result)
	default:
		return custodyEvent{}, fmt.Errorf("%w: read-back inconclusive after ambiguity", ErrCustodyPending)
	}
}

// custodyGetEvent reads one event's full body by its provider identifier under
// the given stable operation identity.
func (c *Client) custodyGetEvent(ctx context.Context, memberSub, stableOperationID, eventID string) (custodyEvent, error) {
	payload := map[string]any{"calendarId": "primary", "eventId": eventID}
	outcome, err := c.custodyExecute(ctx, custody.OperationEventGet, memberSub, stableOperationID, payload)
	if err != nil {
		return custodyEvent{}, err
	}
	if err := c.mapCustodyOutcome(outcome); err != nil {
		return custodyEvent{}, err
	}
	return decodeCustodyEvent(outcome.Result)
}

// ObserveEvent performs a bounded, read-only provider observation through
// Bonbon custody. Calnode receives only event presence and the provider join
// URL; it never receives provider credentials or raw authority material.
func (c *Client) ObserveEvent(ctx context.Context, userID, eventID, stableOperationKey string) (calendar.ProviderEventObservation, error) {
	stableKey := strings.TrimSpace(stableOperationKey)
	providerEventID := strings.TrimSpace(eventID)
	if !c.custodyEnabled() || stableKey == "" || providerEventID == "" || !custody.ValidOpaqueRef(stableKey) {
		return calendar.ProviderEventObservation{}, fmt.Errorf("gcal: managed event observation requires custody and valid identities")
	}
	memberSub, ok := c.destinationMemberSub(ctx, userID)
	if !ok {
		return calendar.ProviderEventObservation{}, nil
	}
	event, err := c.custodyGetEvent(ctx, memberSub, stableKey, providerEventID)
	if err != nil {
		if isNoConn(err) {
			return calendar.ProviderEventObservation{}, nil
		}
		return calendar.ProviderEventObservation{}, err
	}
	return calendar.ProviderEventObservation{Present: true, JoinURL: event.meetLink()}, nil
}

// custodyCreateEvent performs the booking create/upsert: deterministic event
// ID derived from Calnode's own stable operation identity so retries and
// reconciler heals converge on one provider event.
func (c *Client) custodyCreateEvent(ctx context.Context, userID string, p calendar.CreateEventParams) (string, string, error) {
	stableKey := strings.TrimSpace(p.StableOperationKey)
	if stableKey == "" || !custody.ValidOpaqueRef(stableKey) {
		return "", "", fmt.Errorf("custody: create requires a valid StableOperationKey (fail-closed)")
	}
	memberSub, ok := c.destinationMemberSub(ctx, userID)
	if !ok {
		return "", "", nil // identical to direct-mode no-destination semantics
	}
	eventID := custodyEventID(stableKey)
	result, err := c.custodyUpsertEventBody(ctx, memberSub, stableKey, buildCalEventReq(p), eventID)
	if err != nil {
		if isNoConn(err) {
			return "", "", nil
		}
		return "", "", err
	}
	return result.ID, result.meetLink(), nil
}

// custodyUpdateEvent moves start/end (and optionally location) by reading the
// authoritative current body through custody, overriding the moved fields, and
// upserting under the update's stable identity. The custody route exposes PUT
// semantics, so preserving the stored body is response-mapping work, not new
// scheduling authority.
func (c *Client) custodyUpdateEvent(ctx context.Context, userID, eventID string, start, end time.Time, location *string) error {
	if strings.TrimSpace(eventID) == "" {
		return nil
	}
	memberSub, ok := c.destinationMemberSub(ctx, userID)
	if !ok {
		return nil // no destination connection: direct-mode parity
	}
	stableID := "upd:" + eventID
	current, err := c.custodyGetEvent(ctx, memberSub, stableID, eventID)
	if err != nil {
		if isNoConn(err) {
			return nil
		}
		return err
	}
	body := jsonMap(current.raw)
	if !start.IsZero() && !end.IsZero() {
		body["start"] = map[string]any{"dateTime": start.UTC().Format(time.RFC3339), "timeZone": "UTC"}
		body["end"] = map[string]any{"dateTime": end.UTC().Format(time.RFC3339), "timeZone": "UTC"}
	}
	if location != nil {
		body["location"] = *location
	}
	delete(body, "calendarId")
	delete(body, "eventId")
	payload := body
	payload["calendarId"] = "primary"
	payload["eventId"] = eventID
	outcome, err := c.custodyExecute(ctx, custody.OperationEventUpsert, memberSub, stableID, payload)
	if err != nil {
		return err
	}
	if outcome.Kind == custody.OutcomeAmbiguous {
		_, err := c.custodyReadBackAfterAmbiguity(ctx, memberSub, stableID, eventID)
		return err
	}
	return c.mapCustodyOutcome(outcome)
}

// custodyCancelEvent cancels by stable identity; on ambiguity it reads back and
// pends unless the read proves convergence. It NEVER re-issues the cancel
// within the same invocation.
func (c *Client) custodyCancelEvent(ctx context.Context, userID, eventID string) error {
	if strings.TrimSpace(eventID) == "" {
		return nil
	}
	memberSub, ok := c.destinationMemberSub(ctx, userID)
	if !ok {
		return nil
	}
	stableID := "del:" + eventID
	payload := map[string]any{"calendarId": "primary", "eventId": eventID}
	outcome, err := c.custodyExecute(ctx, custody.OperationEventCancel, memberSub, stableID, payload)
	if err != nil {
		return err
	}
	if outcome.Kind == custody.OutcomeAmbiguous {
		c.logger.Warn("custody: cancel ambiguous; converging via event_get read-back",
			"stable_operation_id", stableID, "event_id", eventID)
		read, readErr := c.custodyExecute(ctx, custody.OperationEventGet, memberSub, stableID, payload)
		if readErr != nil {
			return fmt.Errorf("%w: cancel read-back transport error", ErrCustodyPending)
		}
		if read.Kind == custody.OutcomeAccepted || read.Kind == custody.OutcomeReplayed {
			return fmt.Errorf("%w: cancel still present at provider", ErrCustodyPending)
		}
		return fmt.Errorf("%w: cancel read-back inconclusive", ErrCustodyPending)
	}
	if err := c.mapCustodyOutcome(outcome); err != nil {
		if isNoConn(err) {
			return nil
		}
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// FreeBusy under custody: batched payload, availability policy untouched.
// ---------------------------------------------------------------------------

type custodyConnRow struct {
	accountEmail string
	calID        string
}

func (c *Client) custodyFreeBusyConnections(ctx context.Context, userID string) ([]custodyConnRow, error) {
	memberSub, ok := c.destinationMemberSub(ctx, userID)
	if !ok {
		return nil, nil
	}
	return []custodyConnRow{{accountEmail: memberSub, calID: "primary"}}, nil
}

// custodyFreeBusy is the custody-mode FreeBusy: same union + fail-open posture
// as the direct path — availability policy stays entirely in Calnode.
func (c *Client) custodyFreeBusy(ctx context.Context, userID string, from, to time.Time) ([]slots.Interval, error) {
	conns, err := c.custodyFreeBusyConnections(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []slots.Interval
	for _, conn := range conns {
		calIDs := []string{conn.calID}
		intervals, err := c.custodyFreeBusyForConn(ctx, conn.accountEmail, calIDs, from, to)
		if err != nil {
			c.logger.Warn("custody: freebusy for connection failed, skipping", "user_id", userID, "error", err)
			continue
		}
		out = append(out, intervals...)
	}
	return out, nil
}

func (c *Client) custodyFreeBusyForConn(ctx context.Context, memberSub string, calIDs []string, from, to time.Time) ([]slots.Interval, error) {
	items := make([]map[string]any, 0, len(calIDs))
	for _, id := range calIDs {
		items = append(items, map[string]any{"id": id})
	}
	payload := map[string]any{
		"timeMin": from.UTC().Format(time.RFC3339),
		"timeMax": to.UTC().Format(time.RFC3339),
		"items":   items,
	}
	stableID := fmt.Sprintf("fb:%s:%d-%d", memberSub, from.UnixMilli(), to.UnixMilli())
	outcome, err := c.custodyExecute(ctx, custody.OperationFreeBusy, memberSub, stableID, payload)
	if err != nil {
		return nil, err
	}
	if err := c.mapCustodyOutcome(outcome); err != nil && !isNoConn(err) {
		return nil, err
	}
	var fbr freeBusyResp
	if len(outcome.Result) > 0 {
		if err := json.Unmarshal(outcome.Result, &fbr); err != nil {
			return nil, fmt.Errorf("%w: freebusy result decode", ErrCustodyPending)
		}
	}
	var out []slots.Interval
	for _, cal := range fbr.Calendars {
		for _, b := range cal.Busy {
			s, err1 := time.Parse(time.RFC3339, b.Start)
			e, err2 := time.Parse(time.RFC3339, b.End)
			if err1 != nil || err2 != nil {
				continue
			}
			out = append(out, slots.Interval{Start: s, End: e})
		}
	}
	return out, nil
}
