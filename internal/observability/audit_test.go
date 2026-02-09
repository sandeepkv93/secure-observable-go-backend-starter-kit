package observability

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestBuildAuditEventIncludesRequiredFields(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/auth/local/login", nil)
	req.Header.Set("X-Request-Id", "req-test-1")
	req.RemoteAddr = "127.0.0.1:12345"

	ev := BuildAuditEvent(req, AuditInput{
		EventName:   "auth.local.login",
		ActorUserID: "42",
		TargetType:  "user",
		TargetID:    "42",
		Action:      "login",
		Outcome:     "success",
		Reason:      "credentials_valid",
	})

	if ev.EventVersion != 1 {
		t.Fatalf("expected event version 1, got %d", ev.EventVersion)
	}
	if ev.EventName == "" || ev.ActorUserID == "" || ev.ActorIP == "" || ev.TargetType == "" || ev.TargetID == "" || ev.Action == "" || ev.Outcome == "" || ev.Reason == "" || ev.RequestID == "" || ev.TS == "" {
		t.Fatalf("expected required fields present: %+v", ev)
	}
	if ev.RequestID != "req-test-1" {
		t.Fatalf("unexpected request id: %s", ev.RequestID)
	}
	if _, err := time.Parse(time.RFC3339, ev.TS); err != nil {
		t.Fatalf("expected RFC3339 ts, got %q err=%v", ev.TS, err)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("expected valid event, got %v", err)
	}
}

func TestAuditEventValidateRejectsMissingEventName(t *testing.T) {
	ev := AuditEvent{
		EventVersion: 1,
		ActorUserID:  "42",
		ActorIP:      "127.0.0.1",
		TargetType:   "user",
		TargetID:     "42",
		Action:       "login",
		Outcome:      "success",
		Reason:       "ok",
		RequestID:    "req-1",
		TS:           time.Now().UTC().Format(time.RFC3339),
	}
	if err := ev.Validate(); err == nil {
		t.Fatal("expected validation error for missing event_name")
	}
}
