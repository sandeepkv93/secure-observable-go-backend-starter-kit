package observability

import (
	"fmt"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/trace"
)

func Audit(r *http.Request, event string, attrs ...any) {
	msg := "audit"
	sc := trace.SpanContextFromContext(r.Context())
	if sc.IsValid() {
		msg = fmt.Sprintf("audit trace_id=%s span_id=%s", sc.TraceID().String(), sc.SpanID().String())
	}
	base := []any{
		"event", event,
		"method", r.Method,
		"path", r.URL.Path,
		"request_id", r.Header.Get("X-Request-Id"),
	}
	base = append(base, attrs...)
	slog.InfoContext(r.Context(), msg, base...)
}
