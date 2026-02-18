package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"go.uber.org/mock/gomock"
)

func TestDistributedRateLimiterFailOpenOnBackendError(t *testing.T) {
	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Allow(gomock.Any(), gomock.Any(), gomock.Any()).Return(Decision{}, errors.New("redis down"))

	rl := NewDistributedRateLimiter(
		limiter,
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
	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Allow(gomock.Any(), gomock.Any(), gomock.Any()).Return(Decision{}, errors.New("redis down"))

	rl := NewDistributedRateLimiter(
		limiter,
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
	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Allow(gomock.Any(), gomock.Any(), gomock.Any()).Return(Decision{
		Allowed:    false,
		RetryAfter: 5 * time.Second,
		Remaining:  0,
		ResetAt:    time.Now().Add(5 * time.Second),
	}, nil)

	rl := NewDistributedRateLimiter(
		limiter,
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
	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Allow(gomock.Any(), gomock.Any(), gomock.Any()).Return(Decision{
		Allowed:    true,
		RetryAfter: time.Minute,
		Remaining:  0,
		ResetAt:    time.Now().Add(time.Minute),
	}, nil)

	rl := NewDistributedRateLimiter(
		limiter,
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

	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	lastKey := ""
	limiter.EXPECT().Allow(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, key string, policy RateLimitPolicy) (Decision, error) {
		lastKey = key
		return Decision{
			Allowed:   true,
			Remaining: max(policy.SustainedLimit-1, 0),
			ResetAt:   time.Now().Add(policy.SustainedWindow),
		}, nil
	})

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
	if lastKey != "sub:42" {
		t.Fatalf("expected subject key, got %q", lastKey)
	}
}

func TestSubjectOrIPKeyFuncFallsBackToIPWhenTokenInvalid(t *testing.T) {
	jwtMgr := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	lastKey := ""
	limiter.EXPECT().Allow(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, key string, policy RateLimitPolicy) (Decision, error) {
		lastKey = key
		return Decision{
			Allowed:   true,
			Remaining: max(policy.SustainedLimit-1, 0),
			ResetAt:   time.Now().Add(policy.SustainedWindow),
		}, nil
	})

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
	if lastKey != "10.0.0.1" {
		t.Fatalf("expected IP key fallback, got %q", lastKey)
	}
}

func TestRateLimiterWithPolicyBurstThenSustained(t *testing.T) {
	policy := RateLimitPolicy{
		SustainedLimit:    2,
		SustainedWindow:   200 * time.Millisecond,
		BurstCapacity:     4,
		BurstRefillPerSec: 100,
	}
	rl := NewRateLimiterWithPolicy(policy, nil)
	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.0.0.1:1111"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected request %d to pass, got %d", i+1, rr.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected sustained limiter to block burst overflow, got %d", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Fatal("expected Retry-After on sustained overflow")
	}
}

func TestRequestBypassEvaluatorProbePath(t *testing.T) {
	evaluator := NewRequestBypassEvaluator(RequestBypassConfig{
		EnableInternalProbeBypass: true,
	}, nil)
	if evaluator == nil {
		t.Fatal("expected evaluator")
	}

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	bypass, reason := evaluator(req)
	if !bypass || reason != "internal_probe_path" {
		t.Fatalf("expected probe path bypass, got bypass=%v reason=%q", bypass, reason)
	}
}

func TestRequestBypassEvaluatorTrustedCIDR(t *testing.T) {
	evaluator := NewRequestBypassEvaluator(RequestBypassConfig{
		EnableTrustedActorBypass: true,
		TrustedActorCIDRs:        []string{"10.20.0.0/16"},
	}, nil)
	if evaluator == nil {
		t.Fatal("expected evaluator")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.RemoteAddr = "10.20.1.5:4444"
	bypass, reason := evaluator(req)
	if !bypass || reason != "trusted_actor_cidr" {
		t.Fatalf("expected cidr bypass, got bypass=%v reason=%q", bypass, reason)
	}
}

func TestRequestBypassEvaluatorTrustedSubject(t *testing.T) {
	jwtMgr := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	token, err := jwtMgr.SignAccessToken(999, nil, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	evaluator := NewRequestBypassEvaluator(RequestBypassConfig{
		EnableTrustedActorBypass: true,
		TrustedActorSubjects:     []string{"999"},
	}, jwtMgr)
	if evaluator == nil {
		t.Fatal("expected evaluator")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req.RemoteAddr = "203.0.113.9:8080"
	req.Header.Set("Authorization", "Bearer "+token)
	bypass, reason := evaluator(req)
	if !bypass || reason != "trusted_actor_subject" {
		t.Fatalf("expected trusted subject bypass, got bypass=%v reason=%q", bypass, reason)
	}
}

func TestRateLimiterBypassSkipsLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Allow(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	rl := NewDistributedRateLimiter(
		limiter,
		1,
		time.Minute,
		FailClosed,
		"api",
	).WithBypassEvaluator(func(r *http.Request) (bool, string) {
		return true, "test_bypass"
	})
	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected bypass to allow request, got %d", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "" {
		t.Fatalf("did not expect Retry-After on bypass, got %q", got)
	}
}

func TestRateLimitKeyType(t *testing.T) {
	if got := rateLimitKeyType("sub:42"); got != "subject" {
		t.Fatalf("expected subject key type, got %q", got)
	}
	if got := rateLimitKeyType("10.0.0.1"); got != "ip" {
		t.Fatalf("expected ip key type, got %q", got)
	}
}
