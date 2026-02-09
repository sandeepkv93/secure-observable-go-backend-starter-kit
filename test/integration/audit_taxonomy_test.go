package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
)

func TestAuditTaxonomySchemaAndKeyEndpointEvents(t *testing.T) {
	var logBuf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})

	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "audit-admin@example.com"
			cfg.IdempotencyEnabled = false
		},
	})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "audit-admin@example.com", "Valid#Pass1234")

	resp, env := doJSON(t, client, http.MethodGet, baseURL+"/api/v1/me/sessions", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("list sessions failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/admin/roles", map[string]any{
		"name":        "audit_role",
		"description": "role for audit taxonomy test",
		"permissions": []string{"users:read"},
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("create role failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	csrf := cookieValue(t, client, baseURL, "csrf_token")
	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/logout", nil, map[string]string{
		"X-CSRF-Token": csrf,
	})
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("logout failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	events := parseAuditEvents(t, logBuf.String())
	if len(events) == 0 {
		t.Fatal("expected audit events, found none")
	}
	for _, event := range events {
		assertAuditRequiredFields(t, event)
	}

	assertAuditEventOutcome(t, events, "auth.local.register", "success")
	assertAuditEventOutcome(t, events, "auth.local.login", "success")
	assertAuditEventOutcome(t, events, "session.list", "success")
	assertAuditEventOutcome(t, events, "admin.role.create", "success")
	assertAuditEventOutcome(t, events, "auth.logout", "success")
}

func parseAuditEvents(t *testing.T, logs string) []map[string]any {
	t.Helper()
	events := make([]map[string]any, 0)
	scanner := bufio.NewScanner(strings.NewReader(logs))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if msg, _ := entry["msg"].(string); msg == "audit.event" {
			events = append(events, entry)
		}
	}
	return events
}

func assertAuditRequiredFields(t *testing.T, event map[string]any) {
	t.Helper()
	required := []string{
		"event_name", "event_version", "actor_user_id", "actor_ip", "target_type", "target_id",
		"action", "outcome", "reason", "request_id", "trace_id", "span_id", "ts",
	}
	for _, key := range required {
		v, ok := event[key]
		if !ok {
			t.Fatalf("missing required audit field %q in event %#v", key, event)
		}
		if key == "trace_id" || key == "span_id" {
			continue
		}
		if s, isString := v.(string); isString && strings.TrimSpace(s) == "" {
			t.Fatalf("empty required audit field %q in event %#v", key, event)
		}
	}
}

func assertAuditEventOutcome(t *testing.T, events []map[string]any, eventName, outcome string) {
	t.Helper()
	for _, event := range events {
		gotEventName, _ := event["event_name"].(string)
		gotOutcome, _ := event["outcome"].(string)
		if gotEventName == eventName && gotOutcome == outcome {
			return
		}
	}
	t.Fatalf("expected audit event_name=%q outcome=%q, got events=%#v", eventName, outcome, events)
}
