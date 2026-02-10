package di

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/router"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
)

func TestProvideHTTPServer(t *testing.T) {
	cfg := &config.Config{HTTPPort: "9999"}
	srv := provideHTTPServer(cfg, nil)
	if srv.Addr != ":9999" {
		t.Fatalf("unexpected addr: %s", srv.Addr)
	}
	if srv.ReadTimeout.Seconds() != 10 {
		t.Fatalf("unexpected read timeout: %v", srv.ReadTimeout)
	}
}

func TestProvideRouterDependencies(t *testing.T) {
	cfg := &config.Config{CORSAllowedOrigins: []string{"http://localhost:3000"}, AuthRateLimitPerMin: 10, APIRateLimitPerMin: 100, OTELMetricsEnabled: true}
	dep := provideRouterDependencies(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, cfg)
	if dep.AuthRateLimitRPM != 10 || dep.APIRateLimitRPM != 100 {
		t.Fatalf("unexpected rate limits: %+v", dep)
	}
	if !dep.EnableOTelHTTP {
		t.Fatal("expected otel http enabled")
	}
	if len(dep.CORSOrigins) != 1 || dep.CORSOrigins[0] != "http://localhost:3000" {
		t.Fatalf("unexpected cors origins: %+v", dep.CORSOrigins)
	}
	_ = router.Dependencies(dep)
}

func TestProvideRouteRateLimitPolicies(t *testing.T) {
	cfg := &config.Config{
		RateLimitRedisEnabled:     false,
		RateLimitRedisPrefix:      "rl",
		RateLimitLoginPerMin:      1,
		RateLimitRefreshPerMin:    2,
		RateLimitAdminWritePerMin: 3,
		RateLimitAdminSyncPerMin:  1,
	}
	jwt := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	policies := provideRouteRateLimitPolicies(cfg, nil, jwt, nil)
	if policies == nil {
		t.Fatal("expected route policies")
	}
	required := []string{
		router.RoutePolicyLogin,
		router.RoutePolicyRefresh,
		router.RoutePolicyAdminWrite,
		router.RoutePolicyAdminSync,
	}
	for _, key := range required {
		if policies[key] == nil {
			t.Fatalf("missing policy %s", key)
		}
	}
}

func TestRoutePolicyLoginLimiterEnforcesLimit(t *testing.T) {
	cfg := &config.Config{
		RateLimitRedisEnabled:     false,
		RateLimitRedisPrefix:      "rl",
		RateLimitLoginPerMin:      1,
		RateLimitRefreshPerMin:    2,
		RateLimitAdminWritePerMin: 3,
		RateLimitAdminSyncPerMin:  1,
	}
	jwt := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	policies := provideRouteRateLimitPolicies(cfg, nil, jwt, nil)
	loginLimiter := policies[router.RoutePolicyLogin]
	if loginLimiter == nil {
		t.Fatal("expected login limiter")
	}

	h := loginLimiter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/login", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local/login", nil)
	req2.RemoteAddr = "10.0.0.1:1234"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d", rr2.Code)
	}
}

func TestRoutePolicyAdminWriteUsesSubjectKey(t *testing.T) {
	cfg := &config.Config{
		RateLimitRedisEnabled:     false,
		RateLimitRedisPrefix:      "rl",
		RateLimitLoginPerMin:      1,
		RateLimitRefreshPerMin:    2,
		RateLimitAdminWritePerMin: 1,
		RateLimitAdminSyncPerMin:  1,
	}
	jwt := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	token1, err := jwt.SignAccessToken(101, nil, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("sign token1: %v", err)
	}
	token2, err := jwt.SignAccessToken(202, nil, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("sign token2: %v", err)
	}
	policies := provideRouteRateLimitPolicies(cfg, nil, jwt, nil)
	adminWrite := policies[router.RoutePolicyAdminWrite]
	if adminWrite == nil {
		t.Fatal("expected admin write limiter")
	}

	handler := adminWrite(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req1 := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/roles/1", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	req1.Header.Set("Authorization", "Bearer "+token1)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first admin write to pass, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/roles/1", nil)
	req2.RemoteAddr = "10.0.0.2:1234"
	req2.Header.Set("Authorization", "Bearer "+token1)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected same subject to be limited across IPs, got %d", rr2.Code)
	}

	req3 := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/roles/1", nil)
	req3.RemoteAddr = "10.0.0.1:1234"
	req3.Header.Set("Authorization", "Bearer "+token2)
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("expected different subject to have separate quota, got %d", rr3.Code)
	}
}

func TestBuildRoutePolicyLimiterUsesFallbackKeyWhenEmpty(t *testing.T) {
	cfg := &config.Config{
		RateLimitRedisEnabled: false,
	}
	mw := buildRoutePolicyLimiter(cfg, nil, "x", 1, middleware.FailClosed, "scope", func(*http.Request) string {
		return ""
	}, nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req1 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req1.RemoteAddr = "10.0.0.1:1111"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.RemoteAddr = "10.0.0.1:1111"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected fallback key to enforce limit, got %d", rr2.Code)
	}
}

func TestProvideGlobalRateLimiterUsesSubjectOrIP(t *testing.T) {
	cfg := &config.Config{
		RateLimitRedisEnabled: false,
		APIRateLimitPerMin:    1,
	}
	jwt := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	limiter := provideGlobalRateLimiter(cfg, nil, jwt, nil)
	if limiter == nil {
		t.Fatal("expected global limiter")
	}
	token1, err := jwt.SignAccessToken(11, nil, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("sign token1: %v", err)
	}
	token2, err := jwt.SignAccessToken(22, nil, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("sign token2: %v", err)
	}
	h := limiter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req1 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req1.RemoteAddr = "10.0.0.1:1111"
	req1.Header.Set("Authorization", "Bearer "+token1)
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", rr1.Code)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.RemoteAddr = "10.0.0.2:2222"
	req2.Header.Set("Authorization", "Bearer "+token1)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected same subject to be limited, got %d", rr2.Code)
	}
	req3 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req3.RemoteAddr = "10.0.0.1:1111"
	req3.Header.Set("Authorization", "Bearer "+token2)
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("expected different subject to be allowed, got %d", rr3.Code)
	}
}

func TestRoutePoliciesNoRedisDoNotRequireContext(t *testing.T) {
	cfg := &config.Config{
		RateLimitRedisEnabled:     false,
		RateLimitRedisPrefix:      "rl",
		RateLimitLoginPerMin:      1,
		RateLimitRefreshPerMin:    2,
		RateLimitAdminWritePerMin: 3,
		RateLimitAdminSyncPerMin:  1,
	}
	jwt := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	policies := provideRouteRateLimitPolicies(cfg, nil, jwt, nil)
	for name, mw := range policies {
		if mw == nil {
			t.Fatalf("policy %s is nil", name)
		}
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req = req.WithContext(context.Background())
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}
}

func TestProvideForgotRateLimiterFallback(t *testing.T) {
	cfg := &config.Config{
		RateLimitRedisEnabled:             false,
		AuthPasswordForgotRateLimitPerMin: 5,
	}
	mw := provideForgotRateLimiter(cfg, nil, nil)
	if mw == nil {
		t.Fatal("expected forgot rate limiter middleware")
	}
}

func TestProvideForgotRateLimiterRedisFailClosed(t *testing.T) {
	cfg := &config.Config{
		RateLimitRedisEnabled:             true,
		RateLimitRedisPrefix:              "rl",
		AuthPasswordForgotRateLimitPerMin: 5,
	}
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	mw := provideForgotRateLimiter(cfg, client, nil)
	if mw == nil {
		t.Fatal("expected forgot rate limiter middleware")
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/local/password/forgot", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected fail-closed response when redis unavailable, got %d", rr.Code)
	}
}

func TestProvideApp(t *testing.T) {
	cfg := &config.Config{HTTPPort: "8080"}
	logger := slog.Default()
	srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: time.Second}
	runtime := &observability.Runtime{}

	app := provideApp(cfg, logger, srv, runtime, nil, nil, nil)
	if app == nil {
		t.Fatal("expected app")
	}
	if app.Config != cfg || app.Logger != logger || app.Server != srv || app.Observability != runtime {
		t.Fatal("app dependencies not wired as expected")
	}
}

func TestProvideRedisClientEnabledForAdminListCache(t *testing.T) {
	cfg := &config.Config{
		AdminListCacheEnabled:      false,
		NegativeLookupCacheEnabled: false,
		RateLimitRedisEnabled:      false,
		IdempotencyEnabled:         false,
		RedisDialTimeout:           5 * time.Second,
		RedisReadTimeout:           3 * time.Second,
		RedisWriteTimeout:          3 * time.Second,
		RedisMaxRetries:            3,
		RedisMinRetryBackoff:       8 * time.Millisecond,
		RedisMaxRetryBackoff:       512 * time.Millisecond,
		RedisPoolSize:              10,
		RedisMinIdleConns:          2,
		RedisPoolTimeout:           4 * time.Second,
	}
	client := provideRedisClient(cfg)
	if client != nil {
		t.Fatal("expected nil redis client when all redis-backed features are disabled")
	}

	cfg.AdminListCacheEnabled = true
	cfg.RedisAddr = "localhost:6379"
	client = provideRedisClient(cfg)
	if client == nil {
		t.Fatal("expected redis client when admin list cache is enabled")
	}
	redisClient, ok := client.(*redis.Client)
	if !ok {
		t.Fatalf("expected *redis.Client, got %T", client)
	}
	opts := redisClient.Options()
	if opts.DialTimeout != cfg.RedisDialTimeout {
		t.Fatalf("expected redis dial timeout %v, got %v", cfg.RedisDialTimeout, opts.DialTimeout)
	}
	if opts.ReadTimeout != cfg.RedisReadTimeout {
		t.Fatalf("expected redis read timeout %v, got %v", cfg.RedisReadTimeout, opts.ReadTimeout)
	}
	if opts.WriteTimeout != cfg.RedisWriteTimeout {
		t.Fatalf("expected redis write timeout %v, got %v", cfg.RedisWriteTimeout, opts.WriteTimeout)
	}
	if opts.MaxRetries != cfg.RedisMaxRetries {
		t.Fatalf("expected redis max retries %d, got %d", cfg.RedisMaxRetries, opts.MaxRetries)
	}
	if opts.MinRetryBackoff != cfg.RedisMinRetryBackoff {
		t.Fatalf("expected redis min retry backoff %v, got %v", cfg.RedisMinRetryBackoff, opts.MinRetryBackoff)
	}
	if opts.MaxRetryBackoff != cfg.RedisMaxRetryBackoff {
		t.Fatalf("expected redis max retry backoff %v, got %v", cfg.RedisMaxRetryBackoff, opts.MaxRetryBackoff)
	}
	if opts.PoolSize != cfg.RedisPoolSize {
		t.Fatalf("expected redis pool size %d, got %d", cfg.RedisPoolSize, opts.PoolSize)
	}
	if opts.MinIdleConns != cfg.RedisMinIdleConns {
		t.Fatalf("expected redis min idle conns %d, got %d", cfg.RedisMinIdleConns, opts.MinIdleConns)
	}
	if opts.PoolTimeout != cfg.RedisPoolTimeout {
		t.Fatalf("expected redis pool timeout %v, got %v", cfg.RedisPoolTimeout, opts.PoolTimeout)
	}

	cfg.AdminListCacheEnabled = false
	cfg.NegativeLookupCacheEnabled = true
	client = provideRedisClient(cfg)
	if client == nil {
		t.Fatal("expected redis client when negative lookup cache is enabled")
	}
}

func TestProvideAuthAbuseGuard(t *testing.T) {
	cfg := &config.Config{
		AuthAbuseProtectionEnabled: true,
		AuthAbuseFreeAttempts:      3,
		AuthAbuseBaseDelay:         time.Second,
		AuthAbuseMultiplier:        2,
		AuthAbuseMaxDelay:          5 * time.Minute,
		AuthAbuseResetWindow:       30 * time.Minute,
		AuthAbuseRedisPrefix:       "auth_abuse",
	}
	guard := provideAuthAbuseGuard(cfg, nil)
	if guard == nil {
		t.Fatal("expected in-memory auth abuse guard")
	}

	cfg.AuthAbuseProtectionEnabled = false
	guard = provideAuthAbuseGuard(cfg, nil)
	if guard == nil {
		t.Fatal("expected noop auth abuse guard when disabled")
	}
}

func TestProvideRequestBypassEvaluator(t *testing.T) {
	cfg := &config.Config{
		BypassInternalProbes:    true,
		BypassTrustedActors:     true,
		BypassTrustedActorCIDRs: []string{"10.80.0.0/16"},
	}
	evaluator := provideRequestBypassEvaluator(cfg, nil)
	if evaluator == nil {
		t.Fatal("expected bypass evaluator")
	}
	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	req.RemoteAddr = "10.80.1.20:1234"
	bypass, _ := evaluator(req)
	if !bypass {
		t.Fatal("expected bypass for trusted probe request")
	}
}
