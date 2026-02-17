package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/database"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/handler"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/router"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
)

type oauthProviderStub struct{}

func (oauthProviderStub) AuthCodeURL(string) string { return "" }
func (oauthProviderStub) Exchange(context.Context, string) (*oauth2.Token, error) {
	return nil, errors.New("not implemented")
}
func (oauthProviderStub) FetchUserInfo(context.Context, *oauth2.Token) (*service.OAuthUserInfo, error) {
	return nil, errors.New("not implemented")
}

type apiEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type verificationCaptureNotifier struct {
	mu    sync.Mutex
	token string
	reset string
}

func (n *verificationCaptureNotifier) SendEmailVerification(_ context.Context, notification service.VerificationNotification) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.token = notification.Token
	return nil
}

func (n *verificationCaptureNotifier) LastToken() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.token
}

func (n *verificationCaptureNotifier) SendPasswordReset(_ context.Context, notification service.PasswordResetNotification) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reset = notification.Token
	return nil
}

func (n *verificationCaptureNotifier) LastResetToken() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.reset
}

type authTestServerOptions struct {
	cfgOverride    func(cfg *config.Config)
	verifyNotifier service.EmailVerificationNotifier
	resetNotifier  service.PasswordResetNotifier
	storageSvc     service.StorageService
	adminListCache service.AdminListCacheStore
	negativeCache  service.NegativeLookupCacheStore
	rbacPermCache  service.RBACPermissionCacheStore
	routePolicies  router.RouteRateLimitPolicies
	oauthProvider  service.OAuthProvider
	adminUserSvc   service.UserServiceInterface
}

func TestAuthLifecycleLoginRefreshLogoutRevoked(t *testing.T) {
	baseURL, client, closeFn := newAuthTestServer(t)
	defer closeFn()

	registerBody := map[string]string{
		"email":    "auth-lifecycle@example.com",
		"name":     "Auth Lifecycle",
		"password": "Valid#Pass1234",
	}
	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/register", registerBody, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("register failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	loginBody := map[string]string{
		"email":    registerBody["email"],
		"password": registerBody["password"],
	}
	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", loginBody, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("login failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	assertCookieProps(t, resp, "access_token", "/", true)
	assertCookieProps(t, resp, "refresh_token", "/api/v1/auth", true)
	assertCookieProps(t, resp, "csrf_token", "/", false)

	csrf1 := cookieValue(t, client, baseURL, "csrf_token")
	refresh1 := cookieValue(t, client, baseURL, "refresh_token")

	resp, env = doJSON(t, client, http.MethodGet, baseURL+"/api/v1/me", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("me should be authorized after login, got status=%d", resp.StatusCode)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, map[string]string{
		"X-CSRF-Token": csrf1,
	})
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("refresh failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	csrf2 := cookieValue(t, client, baseURL, "csrf_token")
	if csrf2 == csrf1 {
		t.Fatal("csrf token should rotate on refresh")
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/logout", nil, map[string]string{
		"X-CSRF-Token": csrf2,
	})
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("logout failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	assertClearingCookie(t, resp, "access_token")
	assertClearingCookie(t, resp, "refresh_token")
	assertClearingCookie(t, resp, "csrf_token")

	resp, env = doRaw(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, map[string]string{
		"X-CSRF-Token": csrf1,
	}, []*http.Cookie{
		{Name: "refresh_token", Value: refresh1, Path: "/api/v1/auth"},
		{Name: "csrf_token", Value: csrf1, Path: "/"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected revoked refresh to fail with 401, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "UNAUTHORIZED" {
		t.Fatalf("expected unauthorized error, got %#v", env.Error)
	}

	resp, _ = doJSON(t, client, http.MethodGet, baseURL+"/api/v1/me", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me should be unauthorized after logout, got %d", resp.StatusCode)
	}
}

func TestAuthLifecycleCSRFMiddleware(t *testing.T) {
	baseURL, client, closeFn := newAuthTestServer(t)
	defer closeFn()

	registerAndLogin(t, client, baseURL, "csrf-check@example.com", "Valid#Pass1234")

	resp, body := doRawText(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, nil, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "invalid csrf token") {
		t.Fatalf("expected 403 invalid csrf token (missing header), got status=%d body=%q", resp.StatusCode, body)
	}

	resp, body = doRawText(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, map[string]string{
		"X-CSRF-Token": "wrong",
	}, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "invalid csrf token") {
		t.Fatalf("expected 403 invalid csrf token (wrong header), got status=%d body=%q", resp.StatusCode, body)
	}

	resp, body = doRawText(t, client, http.MethodPost, baseURL+"/api/v1/auth/logout", nil, nil, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "invalid csrf token") {
		t.Fatalf("expected 403 invalid csrf token for logout, got status=%d body=%q", resp.StatusCode, body)
	}

	csrf := cookieValue(t, client, baseURL, "csrf_token")
	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/logout", nil, map[string]string{
		"X-CSRF-Token": csrf,
	})
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("logout with valid csrf should succeed, got status=%d", resp.StatusCode)
	}
}

func TestAuthLifecycleRefreshReuseInvalidatesFamily(t *testing.T) {
	baseURL, client, closeFn := newAuthTestServer(t)
	defer closeFn()

	registerAndLogin(t, client, baseURL, "reuse-check@example.com", "Valid#Pass1234")

	refreshA := cookieValue(t, client, baseURL, "refresh_token")
	csrfA := cookieValue(t, client, baseURL, "csrf_token")

	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, map[string]string{
		"X-CSRF-Token": csrfA,
	})
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("first refresh failed: status=%d", resp.StatusCode)
	}
	refreshB := cookieValue(t, client, baseURL, "refresh_token")
	csrfB := cookieValue(t, client, baseURL, "csrf_token")

	resp, env = doRaw(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, map[string]string{
		"X-CSRF-Token": csrfA,
	}, []*http.Cookie{
		{Name: "refresh_token", Value: refreshA, Path: "/api/v1/auth"},
		{Name: "csrf_token", Value: csrfA, Path: "/"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected replayed refresh token to fail with 401, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "UNAUTHORIZED" {
		t.Fatalf("expected unauthorized envelope on replay, got %#v", env.Error)
	}

	resp, env = doRaw(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, map[string]string{
		"X-CSRF-Token": csrfB,
	}, []*http.Cookie{
		{Name: "refresh_token", Value: refreshB, Path: "/api/v1/auth"},
		{Name: "csrf_token", Value: csrfB, Path: "/"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected family-invalidated refresh token to fail with 401, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "UNAUTHORIZED" {
		t.Fatalf("expected unauthorized envelope after family invalidation, got %#v", env.Error)
	}
}

func newAuthTestServer(t *testing.T) (string, *http.Client, func()) {
	return newAuthTestServerWithOptions(t, authTestServerOptions{})
}

func newAuthTestServerWithOptions(t *testing.T, opts authTestServerOptions) (string, *http.Client, func()) {
	t.Helper()

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := database.Seed(db, ""); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cfg := &config.Config{
		AuthGoogleEnabled:                 false,
		AuthLocalEnabled:                  true,
		AuthLocalRequireEmailVerification: false,
		IdempotencyEnabled:                false,
		IdempotencyRedisEnabled:           false,
		IdempotencyTTL:                    24 * time.Hour,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthEmailVerifyBaseURL:            "http://localhost:3000/verify-email",
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		AuthPasswordResetBaseURL:          "http://localhost:3000/reset-password",
		AuthPasswordForgotRateLimitPerMin: 5,
		AuthAbuseProtectionEnabled:        true,
		AuthAbuseFreeAttempts:             3,
		AuthAbuseBaseDelay:                2 * time.Second,
		AuthAbuseMultiplier:               2.0,
		AuthAbuseMaxDelay:                 5 * time.Minute,
		AuthAbuseResetWindow:              30 * time.Minute,
		BypassInternalProbes:              true,
		BypassTrustedActors:               false,
		BootstrapAdminEmail:               "",
		JWTAccessTTL:                      15 * time.Minute,
		JWTRefreshTTL:                     24 * time.Hour,
	}
	if opts.cfgOverride != nil {
		opts.cfgOverride(cfg)
	}

	userRepo := repository.NewUserRepository(db)
	roleRepo := repository.NewRoleRepository(db)
	permRepo := repository.NewPermissionRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	oauthRepo := repository.NewOAuthRepository(db)
	localCredRepo := repository.NewLocalCredentialRepository(db)

	rbac := service.NewRBACService()
	userSvc := service.NewUserService(userRepo, rbac)
	jwtMgr := security.NewJWTManager(
		"iss",
		"aud",
		"abcdefghijklmnopqrstuvwxyz123456",
		"abcdefghijklmnopqrstuvwxyz654321",
	)
	tokenSvc := service.NewTokenService(jwtMgr, sessionRepo, "pepper-1234567890", 15*time.Minute, 24*time.Hour)
	sessionSvc := service.NewSessionService(sessionRepo, "pepper-1234567890")
	oauthProvider := opts.oauthProvider
	if oauthProvider == nil {
		oauthProvider = oauthProviderStub{}
	}
	oauthSvc := service.NewOAuthService(oauthProvider, userRepo, oauthRepo, roleRepo)
	verifyNotifier := opts.verifyNotifier
	resetNotifier := opts.resetNotifier
	if verifyNotifier == nil || resetNotifier == nil {
		dev := service.NewDevEmailVerificationNotifier(slog.New(slog.NewTextHandler(os.Stdout, nil)))
		if verifyNotifier == nil {
			verifyNotifier = dev
		}
		if resetNotifier == nil {
			resetNotifier = dev
		}
	}
	verificationTokenRepo := repository.NewVerificationTokenRepository(db)
	authSvc := service.NewAuthService(cfg, oauthSvc, tokenSvc, userSvc, roleRepo, localCredRepo, verificationTokenRepo, verifyNotifier, resetNotifier)
	cookieMgr := security.NewCookieManager("", false, "lax")
	if cfg.AuthAbuseBaseDelay <= 0 {
		cfg.AuthAbuseBaseDelay = 2 * time.Second
	}
	if cfg.AuthAbuseMultiplier <= 0 {
		cfg.AuthAbuseMultiplier = 2
	}
	if cfg.AuthAbuseMaxDelay <= 0 {
		cfg.AuthAbuseMaxDelay = 5 * time.Minute
	}
	if cfg.AuthAbuseResetWindow <= 0 {
		cfg.AuthAbuseResetWindow = 30 * time.Minute
	}
	abuseGuard := service.NewInMemoryAuthAbuseGuard(service.AuthAbusePolicy{
		FreeAttempts: cfg.AuthAbuseFreeAttempts,
		BaseDelay:    cfg.AuthAbuseBaseDelay,
		Multiplier:   cfg.AuthAbuseMultiplier,
		MaxDelay:     cfg.AuthAbuseMaxDelay,
		ResetWindow:  cfg.AuthAbuseResetWindow,
	})
	bypassEvaluator := middleware.NewRequestBypassEvaluator(middleware.RequestBypassConfig{
		EnableInternalProbeBypass: cfg.BypassInternalProbes,
		EnableTrustedActorBypass:  cfg.BypassTrustedActors,
		TrustedActorCIDRs:         cfg.BypassTrustedActorCIDRs,
		TrustedActorSubjects:      cfg.BypassTrustedActorSubjects,
	}, jwtMgr)

	authHandler := handler.NewAuthHandler(authSvc, abuseGuard, cookieMgr, bypassEvaluator, "0123456789abcdef0123456789abcdef", cfg.JWTRefreshTTL)
	userHandler := handler.NewUserHandler(userSvc, sessionSvc, opts.storageSvc)
	adminUserSvc := opts.adminUserSvc
	if adminUserSvc == nil {
		adminUserSvc = userSvc
	}
	permissionCache := opts.rbacPermCache
	if permissionCache == nil {
		permissionCache = service.NewInMemoryRBACPermissionCacheStore()
	}
	permissionResolver := service.NewCachedPermissionResolver(permissionCache, userSvc, 5*time.Minute)
	negativeCache := opts.negativeCache
	if negativeCache == nil {
		negativeCache = service.NewNoopNegativeLookupCacheStore()
	}
	var adminHandler *handler.AdminHandler
	if opts.adminListCache != nil {
		adminHandler = handler.NewAdminHandler(adminUserSvc, userRepo, roleRepo, permRepo, rbac, permissionResolver, opts.adminListCache, negativeCache, db, cfg)
	} else {
		adminHandler = handler.NewAdminHandler(adminUserSvc, userRepo, roleRepo, permRepo, rbac, permissionResolver, service.NewNoopAdminListCacheStore(), negativeCache, db, cfg)
	}
	var idempotencyFactory router.IdempotencyMiddlewareFactory
	if cfg.IdempotencyEnabled {
		store := service.NewDBIdempotencyStore(db)
		idemMW := middleware.NewIdempotencyMiddleware(store, cfg.IdempotencyTTL)
		idempotencyFactory = func(scope string) func(http.Handler) http.Handler {
			return idemMW.Middleware(scope)
		}
	}

	r := router.NewRouter(router.Dependencies{
		AuthHandler:                authHandler,
		UserHandler:                userHandler,
		AdminHandler:               adminHandler,
		JWTManager:                 jwtMgr,
		RBACService:                rbac,
		PermissionResolver:         permissionResolver,
		CORSOrigins:                []string{"http://localhost"},
		AuthRateLimitRPM:           1000,
		PasswordForgotRateLimitRPM: 1000,
		APIRateLimitRPM:            1000,
		RouteRateLimitPolicies:     opts.routePolicies,
		Idempotency:                idempotencyFactory,
		EnableOTelHTTP:             false,
	})

	srv := httptest.NewServer(r)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := srv.Client()
	client.Jar = jar

	return srv.URL, client, srv.Close
}

func registerAndLogin(t *testing.T, client *http.Client, baseURL, email, password string) {
	t.Helper()
	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/register", map[string]string{
		"email":    email,
		"name":     "Test User",
		"password": password,
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("register failed status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", map[string]string{
		"email":    email,
		"password": password,
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("login failed status=%d success=%v", resp.StatusCode, env.Success)
	}
}

func doJSON(t *testing.T, client *http.Client, method, url string, body any, headers map[string]string) (*http.Response, apiEnvelope) {
	t.Helper()
	resp, raw := doRawText(t, client, method, url, body, headers, nil)
	var env apiEnvelope
	if len(raw) > 0 {
		_ = json.Unmarshal([]byte(raw), &env)
	}
	return resp, env
}

func doRaw(t *testing.T, client *http.Client, method, url string, body any, headers map[string]string, cookies []*http.Cookie) (*http.Response, apiEnvelope) {
	t.Helper()
	resp, raw := doRawText(t, client, method, url, body, headers, cookies)
	var env apiEnvelope
	if len(raw) > 0 {
		_ = json.Unmarshal([]byte(raw), &env)
	}
	return resp, env
}

func doRawText(t *testing.T, client *http.Client, method, url string, body any, headers map[string]string, cookies []*http.Cookie) (*http.Response, string) {
	t.Helper()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.String()
}

func cookieValue(t *testing.T, client *http.Client, baseURL, name string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/auth/refresh", nil)
	if err != nil {
		t.Fatalf("new request for cookie lookup: %v", err)
	}
	cookies := client.Jar.Cookies(req.URL)
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	t.Fatalf("cookie %q not found", name)
	return ""
}

func assertCookieProps(t *testing.T, resp *http.Response, name, path string, httpOnly bool) {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name != name {
			continue
		}
		if c.Path != path {
			t.Fatalf("cookie %s path mismatch: got %q want %q", name, c.Path, path)
		}
		if c.HttpOnly != httpOnly {
			t.Fatalf("cookie %s HttpOnly mismatch: got %v want %v", name, c.HttpOnly, httpOnly)
		}
		return
	}
	t.Fatalf("cookie %s not found in response", name)
}

func assertClearingCookie(t *testing.T, resp *http.Response, name string) {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == name && c.MaxAge < 0 {
			return
		}
	}
	t.Fatalf("expected clearing cookie for %s", name)
}
