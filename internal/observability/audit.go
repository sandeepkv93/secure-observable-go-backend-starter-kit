package observability

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/trace"
)

const auditEventVersion = 1

type AuditInput struct {
	EventName   string
	ActorUserID string
	TargetType  string
	TargetID    string
	Action      string
	Outcome     string
	Reason      string
}

type AuditEvent struct {
	EventName    string `json:"event_name"`
	EventVersion int    `json:"event_version"`
	ActorUserID  string `json:"actor_user_id"`
	ActorIP      string `json:"actor_ip"`
	TargetType   string `json:"target_type"`
	TargetID     string `json:"target_id"`
	Action       string `json:"action"`
	Outcome      string `json:"outcome"`
	Reason       string `json:"reason"`
	RequestID    string `json:"request_id"`
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	TS           string `json:"ts"`
}

func BuildAuditEvent(r *http.Request, in AuditInput) AuditEvent {
	traceID, spanID := traceAndSpanFromContext(r)
	ev := AuditEvent{
		EventName:    strings.TrimSpace(in.EventName),
		EventVersion: auditEventVersion,
		ActorUserID:  defaultString(strings.TrimSpace(in.ActorUserID), "anonymous"),
		ActorIP:      actorIP(r),
		TargetType:   defaultString(strings.TrimSpace(in.TargetType), "none"),
		TargetID:     defaultString(strings.TrimSpace(in.TargetID), "none"),
		Action:       defaultString(strings.TrimSpace(in.Action), "unknown"),
		Outcome:      defaultString(strings.TrimSpace(in.Outcome), "unknown"),
		Reason:       defaultString(strings.TrimSpace(in.Reason), "none"),
		RequestID:    requestID(r),
		TraceID:      traceID,
		SpanID:       spanID,
		TS:           time.Now().UTC().Format(time.RFC3339),
	}
	return ev
}

func (e AuditEvent) Validate() error {
	if strings.TrimSpace(e.EventName) == "" {
		return errInvalidAuditEvent("event_name is required")
	}
	if e.EventVersion <= 0 {
		return errInvalidAuditEvent("event_version must be > 0")
	}
	if strings.TrimSpace(e.ActorUserID) == "" {
		return errInvalidAuditEvent("actor_user_id is required")
	}
	if strings.TrimSpace(e.ActorIP) == "" {
		return errInvalidAuditEvent("actor_ip is required")
	}
	if strings.TrimSpace(e.TargetType) == "" {
		return errInvalidAuditEvent("target_type is required")
	}
	if strings.TrimSpace(e.TargetID) == "" {
		return errInvalidAuditEvent("target_id is required")
	}
	if strings.TrimSpace(e.Action) == "" {
		return errInvalidAuditEvent("action is required")
	}
	if strings.TrimSpace(e.Outcome) == "" {
		return errInvalidAuditEvent("outcome is required")
	}
	if strings.TrimSpace(e.Reason) == "" {
		return errInvalidAuditEvent("reason is required")
	}
	if strings.TrimSpace(e.RequestID) == "" {
		return errInvalidAuditEvent("request_id is required")
	}
	if strings.TrimSpace(e.TS) == "" {
		return errInvalidAuditEvent("ts is required")
	}
	if _, err := time.Parse(time.RFC3339, e.TS); err != nil {
		return errInvalidAuditEvent("ts must be RFC3339 UTC")
	}
	return nil
}

type invalidAuditEventError string

func (e invalidAuditEventError) Error() string { return string(e) }

func errInvalidAuditEvent(msg string) error {
	return invalidAuditEventError(msg)
}

func EmitAudit(r *http.Request, in AuditInput, attrs ...any) {
	ev := BuildAuditEvent(r, in)
	if err := ev.Validate(); err != nil {
		slog.ErrorContext(r.Context(), "audit.schema.invalid",
			"error", err.Error(),
			"event_name", ev.EventName,
			"request_id", ev.RequestID,
		)
		return
	}
	base := []any{
		"event_name", ev.EventName,
		"event_version", ev.EventVersion,
		"actor_user_id", ev.ActorUserID,
		"actor_ip", ev.ActorIP,
		"target_type", ev.TargetType,
		"target_id", ev.TargetID,
		"action", ev.Action,
		"outcome", ev.Outcome,
		"reason", ev.Reason,
		"request_id", ev.RequestID,
		"trace_id", ev.TraceID,
		"span_id", ev.SpanID,
		"ts", ev.TS,
	}
	base = append(base, attrs...)
	slog.InfoContext(r.Context(), "audit.event", base...)
}

func ActorUserID(userID uint) string {
	if userID == 0 {
		return "anonymous"
	}
	return strconv.FormatUint(uint64(userID), 10)
}

func traceAndSpanFromContext(r *http.Request) (string, string) {
	sc := trace.SpanContextFromContext(r.Context())
	if !sc.IsValid() {
		return "", ""
	}
	return sc.TraceID().String(), sc.SpanID().String()
}

func actorIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if host == "" {
		return "unknown"
	}
	return host
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func requestID(r *http.Request) string {
	if id := chimiddleware.GetReqID(r.Context()); id != "" {
		return id
	}
	return r.Header.Get("X-Request-Id")
}
