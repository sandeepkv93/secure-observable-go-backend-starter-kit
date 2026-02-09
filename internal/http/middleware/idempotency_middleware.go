package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

const idempotencyHeader = "Idempotency-Key"

type IdempotencyMiddleware struct {
	store service.IdempotencyStore
	ttl   time.Duration
}

func NewIdempotencyMiddleware(store service.IdempotencyStore, ttl time.Duration) *IdempotencyMiddleware {
	return &IdempotencyMiddleware{store: store, ttl: ttl}
}

func (m *IdempotencyMiddleware) Middleware(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := strings.TrimSpace(r.Header.Get(idempotencyHeader))
			if key == "" {
				observability.RecordIdempotencyEvent(r.Context(), scope, "missing_key")
				response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "missing Idempotency-Key header", nil)
				return
			}
			if len(key) > 128 {
				observability.RecordIdempotencyEvent(r.Context(), scope, "invalid_key")
				response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid Idempotency-Key header", nil)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				observability.RecordIdempotencyEvent(r.Context(), scope, "read_error")
				response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid request payload", nil)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			fingerprint := fingerprintRequest(r, scope, body)

			begin, err := m.store.Begin(r.Context(), scope, key, fingerprint, m.ttl)
			if err != nil {
				observability.RecordIdempotencyEvent(r.Context(), scope, "store_error")
				observability.EmitAudit(r, observability.AuditInput{
					EventName:   "idempotency.check",
					ActorUserID: actorUserIDForAudit(r),
					TargetType:  "idempotency_key",
					TargetID:    shortHash(key),
					Action:      "check",
					Outcome:     "failure",
					Reason:      "store_error",
				}, "scope", scope, "error", err.Error())
				response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "idempotency check failed", nil)
				return
			}

			switch begin.State {
			case service.IdempotencyStateConflict:
				observability.RecordIdempotencyEvent(r.Context(), scope, "conflict")
				observability.EmitAudit(r, observability.AuditInput{
					EventName:   "idempotency.check",
					ActorUserID: actorUserIDForAudit(r),
					TargetType:  "idempotency_key",
					TargetID:    shortHash(key),
					Action:      "check",
					Outcome:     "rejected",
					Reason:      "fingerprint_conflict",
				}, "scope", scope)
				response.Error(w, r, http.StatusConflict, "CONFLICT", "idempotency key reuse with different payload", nil)
				return
			case service.IdempotencyStateInProgress:
				observability.RecordIdempotencyEvent(r.Context(), scope, "in_progress")
				observability.EmitAudit(r, observability.AuditInput{
					EventName:   "idempotency.check",
					ActorUserID: actorUserIDForAudit(r),
					TargetType:  "idempotency_key",
					TargetID:    shortHash(key),
					Action:      "check",
					Outcome:     "rejected",
					Reason:      "request_in_progress",
				}, "scope", scope)
				response.Error(w, r, http.StatusConflict, "CONFLICT", "request with this idempotency key is in progress", nil)
				return
			case service.IdempotencyStateReplay:
				observability.RecordIdempotencyEvent(r.Context(), scope, "replayed")
				observability.EmitAudit(r, observability.AuditInput{
					EventName:   "idempotency.replay",
					ActorUserID: actorUserIDForAudit(r),
					TargetType:  "idempotency_key",
					TargetID:    shortHash(key),
					Action:      "replay",
					Outcome:     "success",
					Reason:      "cached_response",
				}, "scope", scope)
				writeCachedResponse(w, begin.Cached)
				return
			}

			rec := newCaptureWriter(w)
			next.ServeHTTP(rec, r)

			if rec.statusCode == 0 {
				rec.statusCode = http.StatusOK
			}
			observability.RecordIdempotencyEvent(r.Context(), scope, "created")
			if rec.statusCode >= http.StatusInternalServerError {
				return
			}
			if err := m.store.Complete(r.Context(), scope, key, fingerprint, service.CachedHTTPResponse{
				StatusCode:  rec.statusCode,
				ContentType: rec.Header().Get("Content-Type"),
				Body:        rec.body.Bytes(),
			}, m.ttl); err != nil {
				observability.RecordIdempotencyEvent(r.Context(), scope, "store_error")
				observability.EmitAudit(r, observability.AuditInput{
					EventName:   "idempotency.complete",
					ActorUserID: actorUserIDForAudit(r),
					TargetType:  "idempotency_key",
					TargetID:    shortHash(key),
					Action:      "complete",
					Outcome:     "failure",
					Reason:      "store_error",
				}, "scope", scope, "error", err.Error())
			}
		})
	}
}

func writeCachedResponse(w http.ResponseWriter, cached *service.CachedHTTPResponse) {
	if cached == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if cached.ContentType != "" {
		w.Header().Set("Content-Type", cached.ContentType)
	}
	w.Header().Set("X-Idempotency-Replayed", "true")
	w.WriteHeader(cached.StatusCode)
	if len(cached.Body) > 0 {
		_, _ = w.Write(cached.Body)
	}
}

func fingerprintRequest(r *http.Request, scope string, body []byte) string {
	actor := actorForScope(r)
	routePattern := r.URL.Path
	if routeCtx := chi.RouteContext(r.Context()); routeCtx != nil {
		if pattern := routeCtx.RoutePattern(); pattern != "" {
			routePattern = pattern
		}
	}
	raw := strings.Join([]string{
		scope,
		r.Method,
		routePattern,
		actor,
		hex.EncodeToString(hashBytes(body)),
	}, "\n")
	return hex.EncodeToString(hashBytes([]byte(raw)))
}

func actorForScope(r *http.Request) string {
	if claims, ok := ClaimsFromContext(r.Context()); ok {
		return "sub:" + claims.Subject
	}
	return "ip:" + clientIPFromRequest(r)
}

func actorUserIDForAudit(r *http.Request) string {
	if claims, ok := ClaimsFromContext(r.Context()); ok {
		return claims.Subject
	}
	return "anonymous"
}

func clientIPFromRequest(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return r.RemoteAddr
	}
	parts := strings.Split(xff, ",")
	return strings.TrimSpace(parts[0])
}

func hashBytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func shortHash(v string) string {
	full := hex.EncodeToString(hashBytes([]byte(v)))
	if len(full) > 12 {
		return full[:12]
	}
	return full
}

type captureWriter struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func newCaptureWriter(w http.ResponseWriter) *captureWriter {
	return &captureWriter{ResponseWriter: w}
}

func (w *captureWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *captureWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	w.body.Write(p)
	return w.ResponseWriter.Write(p)
}
