package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
)

type fixedWindow struct {
	count       int
	windowStart time.Time
}

type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
	Remaining  int
	ResetAt    time.Time
}

type Limiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (Decision, error)
}

type FailureMode string

const (
	FailOpen   FailureMode = "fail_open"
	FailClosed FailureMode = "fail_closed"
)

type localFixedWindowLimiter struct {
	mu      sync.Mutex
	store   map[string]*fixedWindow
	cleanup time.Time
}

type RateLimiter struct {
	limiter Limiter
	limit   int
	window  time.Duration
	mode    FailureMode
	scope   string
	keyFunc func(r *http.Request) string
}

func NewLocalFixedWindowLimiter() Limiter {
	return &localFixedWindowLimiter{
		store:   make(map[string]*fixedWindow),
		cleanup: time.Now().Add(time.Minute),
	}
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return NewDistributedRateLimiterWithKey(NewLocalFixedWindowLimiter(), limit, window, FailClosed, "local", nil)
}

func NewDistributedRateLimiter(limiter Limiter, limit int, window time.Duration, mode FailureMode, scope string) *RateLimiter {
	return NewDistributedRateLimiterWithKey(limiter, limit, window, mode, scope, nil)
}

func NewRateLimiterWithKey(limit int, window time.Duration, keyFunc func(r *http.Request) string) *RateLimiter {
	return NewDistributedRateLimiterWithKey(NewLocalFixedWindowLimiter(), limit, window, FailClosed, "local", keyFunc)
}

func NewDistributedRateLimiterWithKey(
	limiter Limiter,
	limit int,
	window time.Duration,
	mode FailureMode,
	scope string,
	keyFunc func(r *http.Request) string,
) *RateLimiter {
	if scope == "" {
		scope = "api"
	}
	if keyFunc == nil {
		keyFunc = clientIPKey
	}
	return &RateLimiter{
		limiter: limiter,
		limit:   limit,
		window:  window,
		mode:    mode,
		scope:   scope,
		keyFunc: keyFunc,
	}
}

func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rl.keyFunc(r)
			if key == "" {
				key = clientIPKey(r)
			}
			decision, err := rl.limiter.Allow(r.Context(), key, rl.limit, rl.window)
			if err != nil {
				if rl.mode == FailOpen {
					slog.Warn("rate limiter backend unavailable, allowing request",
						"scope", rl.scope,
						"mode", string(rl.mode),
						"error", err.Error(),
					)
					next.ServeHTTP(w, r)
					return
				}
				writeRateLimitHeaders(w.Header(), rl.limit, 0, time.Now().Add(rl.window))
				w.Header().Set("Retry-After", retryAfterHeader(rl.window))
				response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
				return
			}
			writeRateLimitHeaders(w.Header(), rl.limit, decision.Remaining, decision.ResetAt)
			if !decision.Allowed {
				w.Header().Set("Retry-After", retryAfterHeader(decision.RetryAfter))
				response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func SubjectOrIPKeyFunc(jwtMgr *security.JWTManager) func(r *http.Request) string {
	return func(r *http.Request) string {
		if jwtMgr == nil {
			return clientIPKey(r)
		}

		raw := security.GetCookie(r, "access_token")
		if raw == "" {
			auth := strings.TrimSpace(r.Header.Get("Authorization"))
			if len(auth) >= len("bearer ")+1 && strings.EqualFold(auth[:len("bearer ")], "bearer ") {
				raw = strings.TrimSpace(auth[len("bearer "):])
			}
		}
		if raw == "" {
			return clientIPKey(r)
		}

		claims, err := jwtMgr.ParseAccessToken(raw)
		if err != nil || claims == nil {
			return clientIPKey(r)
		}
		subject := strings.TrimSpace(claims.Subject)
		if subject == "" {
			return clientIPKey(r)
		}
		return "sub:" + subject
	}
}

func (rl *localFixedWindowLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (Decision, error) {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if now.After(rl.cleanup) {
		for k, v := range rl.store {
			if now.Sub(v.windowStart) > 2*window {
				delete(rl.store, k)
			}
		}
		rl.cleanup = now.Add(window)
	}

	entry, ok := rl.store[key]
	if !ok || now.Sub(entry.windowStart) >= window {
		rl.store[key] = &fixedWindow{count: 1, windowStart: now}
		return Decision{
			Allowed:   true,
			Remaining: max(limit-1, 0),
			ResetAt:   now.Add(window),
		}, nil
	}
	if entry.count >= limit {
		retryAfter := window - now.Sub(entry.windowStart)
		if retryAfter < 0 {
			retryAfter = 0
		}
		return Decision{
			Allowed:    false,
			RetryAfter: retryAfter,
			Remaining:  0,
			ResetAt:    now.Add(retryAfter),
		}, nil
	}
	entry.count++
	return Decision{
		Allowed:   true,
		Remaining: max(limit-entry.count, 0),
		ResetAt:   entry.windowStart.Add(window),
	}, nil
}

func clientIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func retryAfterHeader(d time.Duration) string {
	if d <= 0 {
		return "1"
	}
	seconds := int(d.Round(time.Second).Seconds())
	if seconds <= 0 {
		seconds = 1
	}
	return fmt.Sprintf("%d", seconds)
}

func writeRateLimitHeaders(h http.Header, limit int, remaining int, resetAt time.Time) {
	h.Set("X-RateLimit-Limit", fmt.Sprintf("%d", max(limit, 0)))
	h.Set("X-RateLimit-Remaining", fmt.Sprintf("%d", max(remaining, 0)))
	if resetAt.IsZero() {
		resetAt = time.Now().Add(time.Second)
	}
	h.Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt.Unix()))
}
