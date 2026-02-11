package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

type captureHandler struct {
	records []slog.Record
	levels  []slog.Level
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	h.levels = append(h.levels, r.Level)
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func TestStructuredRequestLoggerInfoAndErrorLevels(t *testing.T) {
	orig := slog.Default()
	cap := &captureHandler{}
	slog.SetDefault(slog.New(cap))
	t.Cleanup(func() { slog.SetDefault(orig) })

	r := chi.NewRouter()
	r.Use(StructuredRequestLogger)
	r.Get("/ok", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/boom", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })

	reqOK := httptest.NewRequest(http.MethodGet, "/ok", nil)
	reqOK.RemoteAddr = "198.51.100.10:3456"
	rrOK := httptest.NewRecorder()
	r.ServeHTTP(rrOK, reqOK)

	reqErr := httptest.NewRequest(http.MethodGet, "/boom", nil)
	reqErr.RemoteAddr = "198.51.100.20:7890"
	rrErr := httptest.NewRecorder()
	r.ServeHTTP(rrErr, reqErr)

	if len(cap.records) != 2 {
		t.Fatalf("expected 2 log records, got %d", len(cap.records))
	}
	if cap.levels[0] != slog.LevelInfo {
		t.Fatalf("expected first log to be info, got %v", cap.levels[0])
	}
	if cap.levels[1] != slog.LevelError {
		t.Fatalf("expected second log to be error, got %v", cap.levels[1])
	}

	attrs := recordAttrs(cap.records[0])
	if attrs["route"] != "/ok" || attrs["status"] != "200" {
		t.Fatalf("expected route/status attrs for success, got route=%q status=%q", attrs["route"], attrs["status"])
	}
	if attrs["client_ip"] == "" || attrs["duration_ms"] == "" {
		t.Fatalf("expected client_ip/duration attrs, got %+v", attrs)
	}

	attrs = recordAttrs(cap.records[1])
	if attrs["route"] != "/boom" || attrs["status"] != "500" {
		t.Fatalf("expected route/status attrs for error, got route=%q status=%q", attrs["route"], attrs["status"])
	}
}

func TestStructuredRequestLoggerStatusFallbackTo200(t *testing.T) {
	orig := slog.Default()
	cap := &captureHandler{}
	slog.SetDefault(slog.New(cap))
	t.Cleanup(func() { slog.SetDefault(orig) })

	h := StructuredRequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Intentionally no write header/body.
	}))

	req := httptest.NewRequest(http.MethodGet, "/none", nil)
	req.RemoteAddr = "203.0.113.8:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if len(cap.records) != 1 {
		t.Fatalf("expected one log record, got %d", len(cap.records))
	}
	attrs := recordAttrs(cap.records[0])
	if attrs["status"] != "200" {
		t.Fatalf("expected fallback status 200, got %q", attrs["status"])
	}
}

func recordAttrs(rec slog.Record) map[string]string {
	out := map[string]string{}
	rec.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value.String()
		return true
	})
	return out
}
