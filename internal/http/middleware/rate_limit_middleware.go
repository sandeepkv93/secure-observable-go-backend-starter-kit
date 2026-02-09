package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
)

type fixedWindow struct {
	count       int
	windowStart time.Time
}

type Limiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error)
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
}

func NewLocalFixedWindowLimiter() Limiter {
	return &localFixedWindowLimiter{
		store:   make(map[string]*fixedWindow),
		cleanup: time.Now().Add(time.Minute),
	}
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return NewDistributedRateLimiter(NewLocalFixedWindowLimiter(), limit, window, FailClosed, "local")
}

func NewDistributedRateLimiter(limiter Limiter, limit int, window time.Duration, mode FailureMode, scope string) *RateLimiter {
	if scope == "" {
		scope = "api"
	}
	return &RateLimiter{
		limiter: limiter,
		limit:   limit,
		window:  window,
		mode:    mode,
		scope:   scope,
	}
}

func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := clientIPKey(r)
			allowed, retryAfter, err := rl.limiter.Allow(r.Context(), key, rl.limit, rl.window)
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
				w.Header().Set("Retry-After", retryAfterHeader(rl.window))
				response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", retryAfterHeader(retryAfter))
				response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (rl *localFixedWindowLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
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
		return true, 0, nil
	}
	if entry.count >= limit {
		retryAfter := window - now.Sub(entry.windowStart)
		if retryAfter < 0 {
			retryAfter = 0
		}
		return false, retryAfter, nil
	}
	entry.count++
	return true, 0, nil
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
