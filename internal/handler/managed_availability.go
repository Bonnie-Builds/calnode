package handler

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/calnode/calnode/internal/uid"
)

const maxManagedWeeklyRules = 28

type managedWeeklyRule struct {
	DayOfWeek int    `json:"dayOfWeek"`
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`
}
type managedAvailability struct {
	SchemaVersion string              `json:"schemaVersion"`
	TimeZone      string              `json:"timeZone"`
	Rules         []managedWeeklyRule `json:"rules"`
	Revision      string              `json:"revision"`
}
type managedAvailabilityRequest struct {
	Assertion string `json:"assertion"`
	Update    *struct {
		TimeZone         string              `json:"timeZone"`
		Rules            []managedWeeklyRule `json:"rules"`
		ExpectedRevision string              `json:"expectedRevision"`
	} `json:"update,omitempty"`
}

func validManagedWeeklyRules(rules []managedWeeklyRule) bool {
	if rules == nil || len(rules) > maxManagedWeeklyRules {
		return false
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].DayOfWeek != rules[j].DayOfWeek {
			return rules[i].DayOfWeek < rules[j].DayOfWeek
		}
		return rules[i].StartTime < rules[j].StartTime
	})
	for i, rule := range rules {
		if rule.DayOfWeek < 0 || rule.DayOfWeek > 6 || !validHHMM(rule.StartTime) || !validHHMM(rule.EndTime) || rule.StartTime >= rule.EndTime {
			return false
		}
		if i > 0 && rules[i-1].DayOfWeek == rule.DayOfWeek && rules[i-1].EndTime > rule.StartTime {
			return false
		}
	}
	return true
}

func readManagedAvailability(tx *sql.Tx, userID string) (managedAvailability, error) {
	result := managedAvailability{SchemaVersion: "1", Rules: make([]managedWeeklyRule, 0)}
	if err := tx.QueryRow(`SELECT iana_timezone FROM users WHERE id = ? AND archived_at IS NULL AND is_managed_member = 1`, userID).Scan(&result.TimeZone); err != nil {
		return result, err
	}
	rows, err := tx.Query(`SELECT day_of_week,start_time,end_time FROM availability_rules WHERE user_id = ? AND event_type_id IS NULL ORDER BY day_of_week,start_time,end_time LIMIT ?`, userID, maxManagedWeeklyRules+1)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var rule managedWeeklyRule
		if err := rows.Scan(&rule.DayOfWeek, &rule.StartTime, &rule.EndTime); err != nil {
			return result, err
		}
		result.Rules = append(result.Rules, rule)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if len(result.Rules) > maxManagedWeeklyRules {
		return result, errors.New("availability rule limit exceeded")
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(payload)
	result.Revision = hex.EncodeToString(digest[:])
	return result, nil
}

// ManagedAvailability uses the existing one-time managed assertion boundary.
// Calnode remains the sole owner of weekly hours and timezone. Updates replace
// only this exact member's global rules, atomically with timezone; event-specific
// rules and date overrides are retained. Revision checks prevent stale editors
// from silently overwriting changes made in another tab.
func (h *Handler) ManagedAvailability(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	if !h.bonnieManagedMode {
		h.writeCodedError(w, 404, "not_found", "not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, managedAssertionMaxBody+8<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request managedAvailabilityRequest
	if err := decoder.Decode(&request); err != nil {
		h.writeCodedError(w, 400, "invalid_request", "availability request is invalid")
		return
	}
	var trailing json.RawMessage
	if decoder.Decode(&trailing) != io.EOF {
		h.writeCodedError(w, 400, "invalid_request", "availability request is invalid")
		return
	}
	claims, err := h.verifyManagedAssertion(r.Context(), request.Assertion)
	if err != nil {
		h.writeCodedError(w, 401, "managed_assertion_rejected", "assertion rejected")
		return
	}
	consumed, err := h.consumeJTI(r.Context(), claims.JTI)
	if err != nil {
		h.writeCodedError(w, 503, "availability_unavailable", "availability is unavailable")
		return
	}
	if !consumed {
		h.writeCodedError(w, 401, "managed_assertion_rejected", "assertion rejected")
		return
	}
	userID, found := h.getActiveManagedMemberBySub(r.Context(), claims.Sub)
	if !found {
		h.writeCodedError(w, 403, "managed_member_required", "managed member required")
		return
	}
	if request.Update != nil {
		_, zoneErr := time.LoadLocation(request.Update.TimeZone)
		if request.Update.TimeZone == "" || zoneErr != nil || len(request.Update.ExpectedRevision) != 64 || !validManagedWeeklyRules(request.Update.Rules) {
			h.writeCodedError(w, 422, "invalid_availability", "choose valid, non-overlapping hours and a timezone")
			return
		}
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		h.writeCodedError(w, 503, "availability_unavailable", "availability is unavailable")
		return
	}
	defer tx.Rollback()
	result, err := readManagedAvailability(tx, userID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "read managed availability", "error", err)
		h.writeCodedError(w, 503, "availability_unavailable", "availability is unavailable")
		return
	}
	if update := request.Update; update != nil {
		if result.Revision != update.ExpectedRevision {
			h.writeCodedError(w, 409, "availability_changed", "availability changed; reload before saving")
			return
		}
		if _, err = tx.Exec(`DELETE FROM availability_rules WHERE user_id = ? AND event_type_id IS NULL`, userID); err == nil {
			for _, rule := range update.Rules {
				_, err = tx.Exec(`INSERT INTO availability_rules (id,user_id,event_type_id,day_of_week,start_time,end_time) VALUES (?,?,NULL,?,?,?)`, uid.New(), userID, rule.DayOfWeek, rule.StartTime, rule.EndTime)
				if err != nil {
					break
				}
			}
		}
		if err == nil {
			_, err = tx.Exec(`UPDATE users SET iana_timezone = ? WHERE id = ? AND archived_at IS NULL`, update.TimeZone, userID)
		}
		if err == nil {
			result, err = readManagedAvailability(tx, userID)
		}
		if err != nil {
			h.logger.ErrorContext(r.Context(), "save managed availability", "error", err)
			h.writeCodedError(w, 503, "availability_unavailable", "availability could not be saved")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		h.writeCodedError(w, 503, "availability_unavailable", "availability could not be saved")
		return
	}
	h.writeJSON(w, 200, result)
}
