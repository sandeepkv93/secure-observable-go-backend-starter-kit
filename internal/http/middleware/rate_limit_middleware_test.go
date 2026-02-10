package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
)

type mockLimiter struct {
	allow bool
	retry time.Duration
	err   error
}

func (m mockLimiter) Allow(context.Context, string, int, time.Duration) (Decision, error) {
	return Decision{
		Allowed:    m.allow,
		RetryAfter: m.retry,
		Remaining:  0,
		ResetAt:    time.Now().Add(m.retry),
	}, m.err
}

type recordingLimiter struct {
	lastKey string
	allow   bool
}

func (r *recordingLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (Decision, error) {
	r.lastKey = key
	return Decision{
		Allowed:   r.allow,
		Remaining: max(limit-1, 0),
		ResetAt:   time.Now().Add(window),
	}, nil
}

func TestDistributedRateLimiterFailOpenOnBackendError(t *testing.T) {
	rl := NewDistributedRateLimiter(
		mockLimiter{err: errors.New("redis down")},
		10,
		time.Minute,
		FailOpen,
		"api",
	)
	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected fail-open to allow request, got %d", rr.Code)
	}
}

func TestDistributedRateLimiterFailClosedOnBackendError(t *testing.T) {
	rl := NewDistributedRateLimiter(
		mockLimiter{err: errors.New("redis down")},
		10,
		time.Minute,
		FailClosed,
		"auth",
	)
	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected fail-closed to reject request, got %d", rr.Code)
	}
}

func TestDistributedRateLimiterDeniedSetsRetryAfter(t *testing.T) {
	rl := NewDistributedRateLimiter(
		mockLimiter{allow: false, retry: 5 * time.Second},
		1,
		time.Minute,
		FailClosed,
		"api",
	)
	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Fatal("expected Retry-After header")
	}
	if got := rr.Header().Get("X-RateLimit-Limit"); got != "1" {
		t.Fatalf("expected X-RateLimit-Limit=1, got %q", got)
	}
	if got := rr.Header().Get("X-RateLimit-Remaining"); got != "0" {
		t.Fatalf("expected X-RateLimit-Remaining=0, got %q", got)
	}
	if got := rr.Header().Get("X-RateLimit-Reset"); got == "" {
		t.Fatal("expected X-RateLimit-Reset header")
	} else if _, err := strconv.ParseInt(got, 10, 64); err != nil {
		t.Fatalf("expected numeric X-RateLimit-Reset, got %q", got)
	}
}

func TestDistributedRateLimiterAllowedSetsRateLimitHeaders(t *testing.T) {
	rl := NewDistributedRateLimiter(
		mockLimiter{allow: true, retry: time.Minute},
		3,
		time.Minute,
		FailClosed,
		"api",
	)
	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("X-RateLimit-Limit"); got != "3" {
		t.Fatalf("expected X-RateLimit-Limit=3, got %q", got)
	}
	if got := rr.Header().Get("X-RateLimit-Remaining"); got != "0" {
		t.Fatalf("expected X-RateLimit-Remaining=0 from mock limiter, got %q", got)
	}
	if got := rr.Header().Get("X-RateLimit-Reset"); got == "" {
		t.Fatal("expected X-RateLimit-Reset header")
	}
	if got := rr.Header().Get("Retry-After"); got != "" {
		t.Fatalf("did not expect Retry-After on allowed response, got %q", got)
	}
}

func TestSubjectOrIPKeyFuncUsesSubjectWhenAccessTokenValid(t *testing.T) {
	jwtMgr := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	token, err := jwtMgr.SignAccessToken(42, nil, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}

	limiter := &recordingLimiter{allow: true}
	rl := NewDistributedRateLimiterWithKey(
		limiter,
		10,
		time.Minute,
		FailClosed,
		"api",
		SubjectOrIPKeyFunc(jwtMgr),
	)

	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected request to pass, got %d", rr.Code)
	}
	if limiter.lastKey != "sub:42" {
		t.Fatalf("expected subject key, got %q", limiter.lastKey)
	}
}

func TestSubjectOrIPKeyFuncFallsBackToIPWhenTokenInvalid(t *testing.T) {
	jwtMgr := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	limiter := &recordingLimiter{allow: true}
	rl := NewDistributedRateLimiterWithKey(
		limiter,
		10,
		time.Minute,
		FailClosed,
		"api",
		SubjectOrIPKeyFunc(jwtMgr),
	)

	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	req.Header.Set("Authorization", "Bearer not-a-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected request to pass, got %d", rr.Code)
	}
	if limiter.lastKey != "10.0.0.1" {
		t.Fatalf("expected IP key fallback, got %q", limiter.lastKey)
	}
}
