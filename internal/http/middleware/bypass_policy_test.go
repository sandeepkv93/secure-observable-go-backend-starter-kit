package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
)

func TestNewRequestBypassEvaluatorIgnoresInvalidCIDRsAndCanReturnNil(t *testing.T) {
	eval := NewRequestBypassEvaluator(RequestBypassConfig{
		EnableTrustedActorBypass: true,
		TrustedActorCIDRs:        []string{"not-a-cidr", "", "300.1.1.1/8"},
	}, nil)
	if eval != nil {
		t.Fatal("expected nil evaluator when trusted bypass has no valid cidrs/subjects and probes disabled")
	}
}

func TestRequestBypassEvaluatorMethodPathAndNilRequest(t *testing.T) {
	eval := NewRequestBypassEvaluator(RequestBypassConfig{EnableInternalProbeBypass: true}, nil)
	if eval == nil {
		t.Fatal("expected evaluator")
	}

	if bypass, reason := eval(nil); bypass || reason != "" {
		t.Fatalf("nil request should not bypass, got bypass=%v reason=%q", bypass, reason)
	}

	req := httptest.NewRequest(http.MethodPost, "/health/live", nil)
	if bypass, reason := eval(req); !bypass || reason != "internal_probe_path" {
		t.Fatalf("health/live should bypass regardless of method, got bypass=%v reason=%q", bypass, reason)
	}

	req = httptest.NewRequest(http.MethodGet, "/Health/Ready", nil)
	if bypass, reason := eval(req); !bypass || reason != "internal_probe_path" {
		t.Fatalf("path matching should be case-insensitive, got bypass=%v reason=%q", bypass, reason)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	if bypass, reason := eval(req); bypass || reason != "" {
		t.Fatalf("non-probe path should not bypass, got bypass=%v reason=%q", bypass, reason)
	}
}

func TestRequestBypassEvaluatorTrustedSubjectNormalizationAndFallback(t *testing.T) {
	jwtMgr := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	tok, err := jwtMgr.SignAccessToken(7, nil, nil, time.Minute)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	eval := NewRequestBypassEvaluator(RequestBypassConfig{
		EnableTrustedActorBypass: true,
		TrustedActorSubjects:     []string{" 7 ", ""},
	}, jwtMgr)
	if eval == nil {
		t.Fatal("expected evaluator")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if bypass, reason := eval(req); !bypass || reason != "trusted_actor_subject" {
		t.Fatalf("expected trusted subject bypass, got bypass=%v reason=%q", bypass, reason)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer bad.token")
	if bypass, reason := eval(req); bypass || reason != "" {
		t.Fatalf("invalid token should not bypass, got bypass=%v reason=%q", bypass, reason)
	}
}
