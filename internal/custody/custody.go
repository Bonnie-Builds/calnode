// Package custody is the fork-side remote transport adapter for Bonbon's
// operation-shaped calendar custody boundary (frozen transport contract,
// Phase 0; Orchestrator Fork Adapter Contract, Phase 3).
//
// Remote-transport-only: it builds allowlisted operation requests, posts them
// to the configured Bonbon endpoint, and maps typed responses. It carries NO
// credential material, NO credential-descriptor kind field, and NO kind
// branches — by construction, the request envelope has no such fields.
// Availability policy, booking state, correlation semantics, calendar
// rendering, and transactional mail remain outside this package.
package custody

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// SchemaVersion is the custody request envelope version.
const SchemaVersion = 1

// Operation is one of the four allowlisted custody operations (frozen contract).
type Operation string

const (
	OperationFreeBusy    Operation = "calendar.free_busy"
	OperationEventGet    Operation = "calendar.event_get"
	OperationEventUpsert Operation = "calendar.event_upsert"
	OperationEventCancel Operation = "calendar.event_cancel"
)

// Valid reports whether op is on the frozen allowlist. Any other value must be
// refused locally, pre-network.
func (o Operation) Valid() bool {
	switch o {
	case OperationFreeBusy, OperationEventGet, OperationEventUpsert, OperationEventCancel:
		return true
	}
	return false
}

// SafeState mirrors the frozen refusal/safe-state taxonomy. The set is closed:
// an unknown token from Bonbon fails closed to provider_unavailable so it can
// never flip stored readiness or invent a new terminal state.
type SafeState string

const (
	StateMissing               SafeState = "missing"
	StateRevoked               SafeState = "revoked"
	StateWrongAccount          SafeState = "wrong_account"
	StateWrongMember           SafeState = "wrong_member"
	StateMissingScope          SafeState = "missing_scope"
	StateWorkspaceRequired     SafeState = "workspace_required"
	StateExpired               SafeState = "expired"
	StateTransportUnauthorized SafeState = "transport_unauthorized"
	StateMemberUnavailable     SafeState = "member_unavailable"
	StateProviderUnavailable   SafeState = "provider_unavailable"
)

// ProviderErrorClass is the opaque typed error-class token from the frozen
// contract (e.g. none, network, quota_exhausted). It carries no provider body
// text — never did, never will.
type ProviderErrorClass string

// ReconciliationEventGetReadBack is Bonbon's directive to converge an
// ambiguous upsert/cancel via calendar.event_get plus Calnode's authoritative
// booking read-back (never an effect-retrying call).
const ReconciliationEventGetReadBack = "calnode_event_get_read_back"

var (
	opaqueRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
	memberSubPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	maxOpaqueRefLen  = 512
	minTTL, maxTTL   = 1, 60
)

// Request carries ONLY the contract's bound fields for one operation. There is
// deliberately no credential, kind, scope, or token field on this struct: the
// envelope cannot leak what it does not hold.
type Request struct {
	Operation         Operation
	CompanyRef        string
	InstanceRef       string
	MemberSub         string
	StableOperationID string
	// TTLMinutes is optional (0 omits it); Bonbon derives and clamps its own
	// effective TTL regardless of any caller value.
	TTLMinutes int
	Payload    map[string]any
}

// Validate enforces every bound-field rule locally so malformed envelopes fail
// closed before any network I/O.
func (r Request) Validate() error {
	if !r.Operation.Valid() {
		return fmt.Errorf("custody: operation %q not allowlisted", r.Operation)
	}
	if !ValidOpaqueRef(r.CompanyRef) {
		return fmt.Errorf("custody: companyRef invalid")
	}
	if !ValidOpaqueRef(r.InstanceRef) {
		return fmt.Errorf("custody: instanceRef invalid")
	}
	if !memberSubPattern.MatchString(r.MemberSub) || len(r.MemberSub) > 320 {
		return fmt.Errorf("custody: memberSub must be the provisioned member email")
	}
	if !ValidOpaqueRef(r.StableOperationID) {
		return fmt.Errorf("custody: stableOperationId invalid")
	}
	if r.TTLMinutes != 0 && (r.TTLMinutes < minTTL || r.TTLMinutes > maxTTL) {
		return fmt.Errorf("custody: ttlMinutes out of range")
	}
	return nil
}

// ValidOpaqueRef implements the contract's opaque-reference rule
// ([A-Za-z0-9][A-Za-z0-9._:/-]*, bounded length).
func ValidOpaqueRef(s string) bool {
	return len(s) > 0 && len(s) <= maxOpaqueRefLen && opaqueRefPattern.MatchString(s)
}

// IdempotencyKey builds the exact frozen-contract key shape. It is immutable
// for the same logical effect; Bonbon refuses reuse with different bound
// fields or payload fingerprint.
func IdempotencyKey(op Operation, companyRef, instanceRef, stableOperationID string) string {
	return "calnode:" + companyRef + ":" + instanceRef + ":" + string(op) + ":" + stableOperationID
}

// Key returns the request's idempotency key in the exact contract shape.
func (r Request) Key() string {
	return IdempotencyKey(r.Operation, r.CompanyRef, r.InstanceRef, r.StableOperationID)
}

// OutcomeKind discriminates the closed result taxonomy.
type OutcomeKind int

const (
	OutcomeAccepted OutcomeKind = iota
	OutcomeReplayed
	OutcomeAmbiguous
	OutcomeRefused
	// OutcomeUnavailable is the transient safe state (network fault, provider
	// 5xx, quota, unparseable response): retryable without duplicating effects.
	OutcomeUnavailable
)

// Outcome is one of: typed operation result | explicit ambiguous result |
// safe refusal | transient unavailable. Raw provider error bodies never cross;
// only taxonomy tokens do.
type Outcome struct {
	Kind               OutcomeKind
	Result             json.RawMessage
	Reconciliation     string             // ambiguous only
	RefusalState       SafeState          // refused/unavailable only
	ProviderErrorClass ProviderErrorClass // refused/unavailable only
}

type wireEnvelope struct {
	SchemaVersion     int            `json:"schemaVersion"`
	Operation         string         `json:"operation"`
	CompanyRef        string         `json:"companyRef"`
	InstanceRef       string         `json:"instanceRef"`
	MemberSub         string         `json:"memberSub"`
	StableOperationID string         `json:"stableOperationId"`
	IdempotencyKey    string         `json:"idempotencyKey"`
	TTLMinutes        *int           `json:"ttlMinutes,omitempty"`
	Payload           map[string]any `json:"payload"`
}

type wireResponse struct {
	Outcome            string          `json:"outcome"`
	Result             json.RawMessage `json:"result"`
	Reconciliation     string          `json:"reconciliation"`
	State              string          `json:"state"`
	ProviderErrorClass string          `json:"providerErrorClass"`
}

// Client posts operation requests to Bonbon's custody transport endpoint.
type Client struct {
	endpoint   string
	httpClient *http.Client
	callerAuth string
}

// NewClient targets one custody operations endpoint (deployment-configured).
func NewClient(endpoint string) *Client {
	return &Client{
		endpoint:   strings.TrimRight(endpoint, "/"),
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// WithCallerAuth attaches one deployment-boundary caller header value. This is
// instance-to-Bonbon plumbing, NOT calendar credential material.
func (c *Client) WithCallerAuth(value string) *Client {
	c.callerAuth = value
	return c
}

// Execute performs exactly one custody call. Protocol-level results are
// always Outcomes; error is non-nil only when the local call itself could not
// be made (e.g. cancelled context).
func (c *Client) Execute(ctx context.Context, req Request) (Outcome, error) {
	if err := req.Validate(); err != nil {
		return refused(StateTransportUnauthorized, "none"), nil
	}
	envelope := wireEnvelope{
		SchemaVersion:     SchemaVersion,
		Operation:         string(req.Operation),
		CompanyRef:        req.CompanyRef,
		InstanceRef:       req.InstanceRef,
		MemberSub:         req.MemberSub,
		StableOperationID: req.StableOperationID,
		IdempotencyKey:    req.Key(),
		Payload:           req.Payload,
	}
	if req.TTLMinutes != 0 {
		ttl := req.TTLMinutes
		envelope.TTLMinutes = &ttl
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return unavailable("unknown"), nil
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/custody/calendar/operations", bytes.NewReader(body))
	if err != nil {
		return unavailable("unknown"), nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.callerAuth != "" {
		httpReq.Header.Set("X-Bonbon-Custody-Caller", c.callerAuth)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return Outcome{}, ctx.Err()
		}
		return unavailable("network"), nil
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return unavailable("network"), nil
	}
	var parsed wireResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return unavailable("unknown"), nil
	}
	switch parsed.Outcome {
	case "accepted", "replayed":
		result := parsed.Result
		if parsed.Result == nil {
			result = json.RawMessage("{}")
		}
		kind := OutcomeAccepted
		if parsed.Outcome == "replayed" {
			kind = OutcomeReplayed
		}
		return Outcome{Kind: kind, Result: result}, nil
	case "ambiguous":
		if parsed.Reconciliation == "" {
			parsed.Reconciliation = ReconciliationEventGetReadBack
		}
		return Outcome{Kind: OutcomeAmbiguous, Reconciliation: parsed.Reconciliation}, nil
	case "refused":
		state := SafeState(strings.TrimSpace(parsed.State))
		if !validSafeState(state) {
			// Closed taxonomy: unknown refusal tokens fail closed as transient.
			return unavailable("unknown"), nil
		}
		class := ProviderErrorClass(strings.TrimSpace(parsed.ProviderErrorClass))
		if class == "" {
			class = "none"
		}
		return refused(state, string(class)), nil
	default:
		return unavailable("unknown"), nil
	}
}

func refused(state SafeState, class string) Outcome {
	return Outcome{
		Kind:               OutcomeRefused,
		RefusalState:       state,
		ProviderErrorClass: ProviderErrorClass(class),
	}
}

func unavailable(class string) Outcome {
	return Outcome{
		Kind:               OutcomeUnavailable,
		RefusalState:       StateProviderUnavailable,
		ProviderErrorClass: ProviderErrorClass(class),
	}
}

func validSafeState(s SafeState) bool {
	switch s {
	case StateMissing, StateRevoked, StateWrongAccount, StateWrongMember,
		StateMissingScope, StateWorkspaceRequired, StateExpired,
		StateTransportUnauthorized, StateMemberUnavailable, StateProviderUnavailable:
		return true
	}
	return false
}
