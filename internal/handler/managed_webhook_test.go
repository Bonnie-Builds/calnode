package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagedCreateMemberWebhookCreatesForExactSubject(t *testing.T) {
	h, database := managedSetup(t)

	ensureBody, _ := json.Marshal(map[string]string{
		"sub":            "sub_webhook_owner",
		"email":          "webhook-owner@example.com",
		"name":           "Webhook Owner",
		"member_api_key": "member-key-0123456789abcdef0123456789abcdef",
	})
	ensureReq := httptest.NewRequest(http.MethodPost, "/v1/managed/members", bytes.NewReader(ensureBody))
	ensureReq.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	ensureRec := httptest.NewRecorder()
	h.RequireManagedOperator(h.ManagedEnsureMember)(ensureRec, ensureReq)
	if ensureRec.Code != http.StatusOK {
		t.Fatalf("ensure member status = %d; want 200 — %s", ensureRec.Code, ensureRec.Body.String())
	}

	body := []byte(`{"url":"https://example.com/bonbon-hook","events":["booking.created","booking.rescheduled","booking.cancelled"]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/managed/members/sub_webhook_owner/webhooks", bytes.NewReader(body))
	req.SetPathValue("sub", "sub_webhook_owner")
	req.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	rec := httptest.NewRecorder()
	h.RequireManagedOperator(h.ManagedCreateMemberWebhook)(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create managed webhook status = %d; want 201 — %s", rec.Code, rec.Body.String())
	}

	var response struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.ID == "" || len(response.Secret) != 64 {
		t.Fatalf("expected one-time webhook id and secret, got id=%q secret_length=%d", response.ID, len(response.Secret))
	}

	var ownerSubject string
	if err := database.QueryRow(`
		SELECT u.managed_subject
		FROM webhooks w JOIN users u ON u.id = w.user_id
		WHERE w.id = ?`, response.ID).Scan(&ownerSubject); err != nil {
		t.Fatalf("query webhook owner: %v", err)
	}
	if ownerSubject != "sub_webhook_owner" {
		t.Fatalf("webhook owner = %q; want exact managed subject", ownerSubject)
	}

	retryReq := httptest.NewRequest(http.MethodPost, "/v1/managed/members/sub_webhook_owner/webhooks", bytes.NewReader(body))
	retryReq.SetPathValue("sub", "sub_webhook_owner")
	retryReq.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	retryRec := httptest.NewRecorder()
	h.RequireManagedOperator(h.ManagedCreateMemberWebhook)(retryRec, retryReq)
	if retryRec.Code != http.StatusCreated {
		t.Fatalf("retry managed webhook status = %d; want 201 — %s", retryRec.Code, retryRec.Body.String())
	}
	var retryResponse struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(retryRec.Body.Bytes(), &retryResponse); err != nil {
		t.Fatalf("decode retry response: %v", err)
	}
	if retryResponse.ID != response.ID || retryResponse.Secret != response.Secret {
		t.Fatalf("operator retry must return the existing managed webhook receipt")
	}
	var webhookCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM webhooks WHERE user_id = (SELECT id FROM users WHERE managed_subject = 'sub_webhook_owner')`).Scan(&webhookCount); err != nil {
		t.Fatalf("count managed webhooks: %v", err)
	}
	if webhookCount != 1 {
		t.Fatalf("managed webhook count = %d; want 1 after retry", webhookCount)
	}
}

func TestManagedCreateMemberWebhookRequiresOperatorAndActiveSubject(t *testing.T) {
	h, _ := managedSetup(t)
	body := []byte(`{"url":"https://example.com/bonbon-hook","events":["booking.created"]}`)

	unauthorizedReq := httptest.NewRequest(http.MethodPost, "/v1/managed/members/sub_missing/webhooks", bytes.NewReader(body))
	unauthorizedReq.SetPathValue("sub", "sub_missing")
	unauthorizedRec := httptest.NewRecorder()
	h.RequireManagedOperator(h.ManagedCreateMemberWebhook)(unauthorizedRec, unauthorizedReq)
	if unauthorizedRec.Code != http.StatusUnauthorized {
		t.Fatalf("missing operator key status = %d; want 401", unauthorizedRec.Code)
	}

	missingReq := httptest.NewRequest(http.MethodPost, "/v1/managed/members/sub_missing/webhooks", bytes.NewReader(body))
	missingReq.SetPathValue("sub", "sub_missing")
	missingReq.Header.Set("X-Operator-Key", "operator-secret-0123456789")
	missingRec := httptest.NewRecorder()
	h.RequireManagedOperator(h.ManagedCreateMemberWebhook)(missingRec, missingReq)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("missing subject status = %d; want 404", missingRec.Code)
	}
}
