package middleware

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/observability"
)

func RequestID(next http.Handler) http.Handler { return chimiddleware.RequestID(next) }

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := map[string]struct{}{}
	for _, o := range allowedOrigins {
		allowed[o] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if _, ok := allowed[origin]; ok {
					observability.RecordMiddlewareValidationEvent(r.Context(), "cors", "allow_origin")
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
				} else {
					observability.RecordMiddlewareValidationEvent(r.Context(), "cors", "rejected_origin")
				}
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, OPTIONS")
			}
			if r.Method == http.MethodOptions {
				observability.RecordMiddlewareValidationEvent(r.Context(), "cors", "preflight")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = &bodyLimitObserver{
				readCloser: http.MaxBytesReader(w, r.Body, maxBytes),
				ctx:        r.Context(),
			}
			next.ServeHTTP(w, r)
		})
	}
}

type bodyLimitObserver struct {
	readCloser io.ReadCloser
	ctx        context.Context
	emitted    bool
}

func (o *bodyLimitObserver) Read(p []byte) (int, error) {
	n, err := o.readCloser.Read(p)
	if err == nil || errors.Is(err, io.EOF) || o.emitted {
		return n, err
	}

	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		observability.RecordMiddlewareValidationEvent(o.ctx, "body_limit", "rejected_too_large")
		o.emitted = true
		return n, err
	}

	observability.RecordMiddlewareValidationEvent(o.ctx, "body_limit", "read_error")
	o.emitted = true
	return n, err
}

func (o *bodyLimitObserver) Close() error {
	return o.readCloser.Close()
}

func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := strings.ToUpper(r.Method)
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie("csrf_token")
		pathGroup := csrfPathGroup(r.URL.Path)
		if err != nil || cookie.Value == "" {
			observability.RecordCSRFValidation(r.Context(), "missing_cookie", pathGroup)
			response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "invalid csrf token", nil)
			return
		}
		if r.Header.Get("X-CSRF-Token") != cookie.Value {
			observability.RecordCSRFValidation(r.Context(), "mismatch", pathGroup)
			response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "invalid csrf token", nil)
			return
		}
		observability.RecordCSRFValidation(r.Context(), "valid", pathGroup)
		next.ServeHTTP(w, r)
	})
}

func csrfPathGroup(rawPath string) string {
	p := strings.Trim(path.Clean(rawPath), "/")
	if p == "." || p == "" {
		return "root"
	}
	parts := strings.Split(p, "/")
	if len(parts) >= 3 && parts[0] == "api" {
		return parts[0] + "/" + parts[2]
	}
	return parts[0]
}
