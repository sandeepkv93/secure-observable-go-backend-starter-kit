package middleware

import (
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

type RateLimiter struct {
	mu      sync.Mutex
	store   map[string]*fixedWindow
	limit   int
	window  time.Duration
	cleanup time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		store:   make(map[string]*fixedWindow),
		limit:   limit,
		window:  window,
		cleanup: time.Now().Add(window),
	}
}

func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := clientIPKey(r)
			if !rl.allow(key) {
				response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (rl *RateLimiter) allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if now.After(rl.cleanup) {
		for k, v := range rl.store {
			if now.Sub(v.windowStart) > 2*rl.window {
				delete(rl.store, k)
			}
		}
		rl.cleanup = now.Add(rl.window)
	}

	entry, ok := rl.store[key]
	if !ok || now.Sub(entry.windowStart) >= rl.window {
		rl.store[key] = &fixedWindow{count: 1, windowStart: now}
		return true
	}
	if entry.count >= rl.limit {
		return false
	}
	entry.count++
	return true
}

func clientIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
