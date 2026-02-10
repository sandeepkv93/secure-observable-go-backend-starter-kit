package integration

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/router"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
)

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	rl := middleware.NewRateLimiter(2, time.Minute)
	r := chi.NewRouter()
	r.With(rl.Middleware()).Get("/x", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 on request %d, got %d", i+1, w.Code)
		}
		if got := w.Header().Get("X-RateLimit-Limit"); got != "2" {
			t.Fatalf("expected X-RateLimit-Limit=2 on request %d, got %q", i+1, got)
		}
		if got := w.Header().Get("X-RateLimit-Remaining"); got == "" {
			t.Fatalf("expected X-RateLimit-Remaining on request %d", i+1)
		}
		if got := w.Header().Get("X-RateLimit-Reset"); got == "" {
			t.Fatalf("expected X-RateLimit-Reset on request %d", i+1)
		} else if _, err := strconv.ParseInt(got, 10, 64); err != nil {
			t.Fatalf("expected numeric X-RateLimit-Reset on request %d, got %q", i+1, got)
		}
		if got := w.Header().Get("Retry-After"); got != "" {
			t.Fatalf("did not expect Retry-After on request %d, got %q", i+1, got)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 got %d", w.Code)
	}
	if got := w.Header().Get("X-RateLimit-Limit"); got != "2" {
		t.Fatalf("expected X-RateLimit-Limit=2 on limited request, got %q", got)
	}
	if got := w.Header().Get("X-RateLimit-Remaining"); got != "0" {
		t.Fatalf("expected X-RateLimit-Remaining=0 on limited request, got %q", got)
	}
	if got := w.Header().Get("X-RateLimit-Reset"); got == "" {
		t.Fatal("expected X-RateLimit-Reset on limited request")
	} else if _, err := strconv.ParseInt(got, 10, 64); err != nil {
		t.Fatalf("expected numeric X-RateLimit-Reset on limited request, got %q", got)
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Fatal("expected Retry-After on limited request")
	}
}

func TestRateLimiterSubjectKeyingAcrossIPs(t *testing.T) {
	jwtMgr := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	subjectLimiter := middleware.NewRateLimiterWithKey(2, time.Minute, middleware.SubjectOrIPKeyFunc(jwtMgr))
	tokenUser1, err := jwtMgr.SignAccessToken(101, nil, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("sign token user1: %v", err)
	}
	tokenUser2, err := jwtMgr.SignAccessToken(202, nil, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("sign token user2: %v", err)
	}

	r := chi.NewRouter()
	r.With(subjectLimiter.Middleware()).Get("/x", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	req1 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	req1.Header.Set("Authorization", "Bearer "+tokenUser1)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first user1 request 200, got %d", w1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.RemoteAddr = "10.0.0.2:1234"
	req2.Header.Set("Authorization", "Bearer "+tokenUser1)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected second user1 request from different IP 200, got %d", w2.Code)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req3.RemoteAddr = "10.0.0.3:1234"
	req3.Header.Set("Authorization", "Bearer "+tokenUser1)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected user1 third request to be limited, got %d", w3.Code)
	}

	req4 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req4.RemoteAddr = "10.0.0.1:1234"
	req4.Header.Set("Authorization", "Bearer "+tokenUser2)
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("expected different user on same IP to have separate quota, got %d", w4.Code)
	}
}

func TestRoutePolicyMapLoginAndRefreshLimits(t *testing.T) {
	jwtMgr := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	policies := router.RouteRateLimitPolicies{
		router.RoutePolicyLogin:   middleware.NewRateLimiter(1, time.Minute).Middleware(),
		router.RoutePolicyRefresh: middleware.NewRateLimiterWithKey(1, time.Minute, middleware.SubjectOrIPKeyFunc(jwtMgr)).Middleware(),
	}
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		routePolicies: policies,
	})
	defer closeFn()

	registerOnly(t, client, baseURL, "route-policy-login-refresh@example.com")

	loginBody := map[string]string{
		"email":    "route-policy-login-refresh@example.com",
		"password": "Valid#Pass1234",
	}
	resp, _ := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", loginBody, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected first login attempt after register flow to pass, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", loginBody, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected second login attempt to be limited by route policy, got %d", resp.StatusCode)
	}

	csrf := cookieValue(t, client, baseURL, "csrf_token")
	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, map[string]string{
		"X-CSRF-Token": csrf,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected first refresh to pass, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, map[string]string{
		"X-CSRF-Token": cookieValue(t, client, baseURL, "csrf_token"),
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected second refresh to be limited by route policy, got %d", resp.StatusCode)
	}
}

func TestRoutePolicyMapAdminWriteAndSyncLimits(t *testing.T) {
	jwtMgr := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	policies := router.RouteRateLimitPolicies{
		router.RoutePolicyAdminWrite: middleware.NewRateLimiterWithKey(1, time.Minute, middleware.SubjectOrIPKeyFunc(jwtMgr)).Middleware(),
		router.RoutePolicyAdminSync:  middleware.NewRateLimiterWithKey(1, time.Minute, middleware.SubjectOrIPKeyFunc(jwtMgr)).Middleware(),
	}
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		routePolicies: policies,
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "route-policy-admin@example.com"
		},
	})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "route-policy-admin@example.com", "Valid#Pass1234")

	resp, _ := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/admin/roles", map[string]any{
		"name":        "route-policy-role-1",
		"description": "policy test role",
		"permissions": []string{"users:read"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected first admin write to pass, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/admin/roles", map[string]any{
		"name":        "route-policy-role-2",
		"description": "policy test role",
		"permissions": []string{"users:read"},
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected second admin write to be limited, got %d", resp.StatusCode)
	}

	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/admin/rbac/sync", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected first sync to pass, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/admin/rbac/sync", nil, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected second sync to be limited, got %d", resp.StatusCode)
	}

}
