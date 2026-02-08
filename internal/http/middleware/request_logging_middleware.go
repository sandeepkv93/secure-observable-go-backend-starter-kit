package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// StructuredRequestLogger emits one structured log line per request using slog.
// This keeps request logs aligned with the app's OTel-enriched logging path.
func StructuredRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}

		requestID := chimiddleware.GetReqID(r.Context())
		routePattern := ""
		if routeCtx := chi.RouteContext(r.Context()); routeCtx != nil {
			routePattern = routeCtx.RoutePattern()
		}

		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"route", routePattern,
			"status", status,
			"bytes", ww.BytesWritten(),
			"duration_ms", float64(time.Since(start).Microseconds()) / 1000.0,
			"request_id", requestID,
			"client_ip", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		}

		if status >= http.StatusInternalServerError {
			slog.ErrorContext(r.Context(), "http.request", attrs...)
			return
		}
		slog.InfoContext(r.Context(), "http.request", attrs...)
	})
}
