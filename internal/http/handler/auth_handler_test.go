package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

type authErrorEnvelope struct {
	Success bool `json:"success"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type stubAuthService struct {
	parseUserIDFn func(subject string) (uint, error)
	refreshFn     func(refreshToken, ua, ip string) (*service.LoginResult, error)
	logoutFn      func(userID uint) error
	changePassFn  func(userID uint, currentPassword, newPassword string) error

	requestVerifyFn func(email string) error
	confirmVerifyFn func(token string) error
	forgotFn        func(email string) error
	resetFn         func(token, newPassword string) error
	loginLocalFn    func(email, password, ua, ip string) (*service.LoginResult, error)
}

func (s *stubAuthService) GoogleLoginURL(state string) string { return "" }

func (s *stubAuthService) LoginWithGoogleCode(code, ua, ip string) (*service.LoginResult, error) {
	return nil, errors.New("not implemented")
}

func (s *stubAuthService) RegisterLocal(email, name, password, ua, ip string) (*service.LoginResult, error) {
	return nil, errors.New("not implemented")
}

func (s *stubAuthService) LoginWithLocalPassword(email, password, ua, ip string) (*service.LoginResult, error) {
	if s.loginLocalFn != nil {
		return s.loginLocalFn(email, password, ua, ip)
	}
	return nil, errors.New("not implemented")
}

func (s *stubAuthService) RequestLocalEmailVerification(email string) error {
	if s.requestVerifyFn != nil {
		return s.requestVerifyFn(email)
	}
	return nil
}

func (s *stubAuthService) ConfirmLocalEmailVerification(token string) error {
	if s.confirmVerifyFn != nil {
		return s.confirmVerifyFn(token)
	}
	return nil
}

func (s *stubAuthService) ForgotLocalPassword(email string) error {
	if s.forgotFn != nil {
		return s.forgotFn(email)
	}
	return nil
}

func (s *stubAuthService) ResetLocalPassword(token, newPassword string) error {
	if s.resetFn != nil {
		return s.resetFn(token, newPassword)
	}
	return nil
}

func (s *stubAuthService) ChangeLocalPassword(userID uint, currentPassword, newPassword string) error {
	if s.changePassFn != nil {
		return s.changePassFn(userID, currentPassword, newPassword)
	}
	return nil
}

func (s *stubAuthService) Refresh(refreshToken, ua, ip string) (*service.LoginResult, error) {
	if s.refreshFn != nil {
		return s.refreshFn(refreshToken, ua, ip)
	}
	return nil, errors.New("not implemented")
}

func (s *stubAuthService) Logout(userID uint) error {
	if s.logoutFn != nil {
		return s.logoutFn(userID)
	}
	return nil
}

func (s *stubAuthService) ParseUserID(subject string) (uint, error) {
	if s.parseUserIDFn != nil {
		return s.parseUserIDFn(subject)
	}
	return 0, errors.New("not implemented")
}

type stubAuthAbuseGuard struct {
	checkFn    func(ctx context.Context, scope service.AuthAbuseScope, identity, ip string) (time.Duration, error)
	registerFn func(ctx context.Context, scope service.AuthAbuseScope, identity, ip string) (time.Duration, error)
	resetFn    func(ctx context.Context, scope service.AuthAbuseScope, identity, ip string) error

	checkCalls    int
	registerCalls int
	resetCalls    int
}

func (s *stubAuthAbuseGuard) Check(ctx context.Context, scope service.AuthAbuseScope, identity, ip string) (time.Duration, error) {
	s.checkCalls++
	if s.checkFn != nil {
		return s.checkFn(ctx, scope, identity, ip)
	}
	return 0, nil
}

func (s *stubAuthAbuseGuard) RegisterFailure(ctx context.Context, scope service.AuthAbuseScope, identity, ip string) (time.Duration, error) {
	s.registerCalls++
	if s.registerFn != nil {
		return s.registerFn(ctx, scope, identity, ip)
	}
	return 0, nil
}

func (s *stubAuthAbuseGuard) Reset(ctx context.Context, scope service.AuthAbuseScope, identity, ip string) error {
	s.resetCalls++
	if s.resetFn != nil {
		return s.resetFn(ctx, scope, identity, ip)
	}
	return nil
}

func withClaims(r *http.Request, sub string) *http.Request {
	claims := &security.Claims{}
	claims.Subject = sub
	ctx := context.WithValue(r.Context(), middleware.ClaimsContextKey, claims)
	return r.WithContext(ctx)
}

func decodeAuthErrorEnvelope(t *testing.T, rr *httptest.ResponseRecorder) authErrorEnvelope {
	t.Helper()
	var env authErrorEnvelope
	if err := json.NewDecoder(rr.Body).Decode(&env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	return env
}

func hasCookie(cookies []*http.Cookie, name string) bool {
	for _, c := range cookies {
		if c.Name == name {
			return true
		}
	}
	return false
}

func isClearedCookie(cookies []*http.Cookie, name string) bool {
	for _, c := range cookies {
		if c.Name == name && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestAuthHandlerLocalChangePasswordBranchesAndCookieSideEffects(t *testing.T) {
	cookieMgr := security.NewCookieManager("", false, "lax")

	t.Run("missing auth context", func(t *testing.T) {
		h := NewAuthHandler(&stubAuthService{}, &stubAuthAbuseGuard{}, cookieMgr, nil, "state", 24*time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", strings.NewReader(`{"current_password":"a","new_password":"b"}`))
		rr := httptest.NewRecorder()

		h.LocalChangePassword(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
		env := decodeAuthErrorEnvelope(t, rr)
		if env.Error == nil || env.Error.Code != "UNAUTHORIZED" {
			t.Fatalf("expected UNAUTHORIZED, got %+v", env.Error)
		}
	})

	t.Run("invalid subject", func(t *testing.T) {
		authSvc := &stubAuthService{parseUserIDFn: func(subject string) (uint, error) {
			return 0, errors.New("bad subject")
		}}
		h := NewAuthHandler(authSvc, &stubAuthAbuseGuard{}, cookieMgr, nil, "state", 24*time.Hour)
		req := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", strings.NewReader(`{"current_password":"a","new_password":"b"}`)), "bad")
		rr := httptest.NewRecorder()

		h.LocalChangePassword(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("service error mappings", func(t *testing.T) {
		cases := []struct {
			name     string
			err      error
			wantCode int
			wantErr  string
		}{
			{name: "not enabled", err: service.ErrLocalAuthDisabled, wantCode: http.StatusNotFound, wantErr: "NOT_ENABLED"},
			{name: "weak password", err: service.ErrWeakPassword, wantCode: http.StatusBadRequest, wantErr: "BAD_REQUEST"},
			{name: "invalid credentials", err: service.ErrInvalidCredentials, wantCode: http.StatusUnauthorized, wantErr: "UNAUTHORIZED"},
			{name: "other", err: errors.New("mismatch"), wantCode: http.StatusBadRequest, wantErr: "BAD_REQUEST"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				authSvc := &stubAuthService{
					parseUserIDFn: func(subject string) (uint, error) { return 77, nil },
					changePassFn:  func(userID uint, currentPassword, newPassword string) error { return tc.err },
				}
				h := NewAuthHandler(authSvc, &stubAuthAbuseGuard{}, cookieMgr, nil, "state", 24*time.Hour)
				req := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", strings.NewReader(`{"current_password":"old","new_password":"new"}`)), "77")
				rr := httptest.NewRecorder()

				h.LocalChangePassword(rr, req)
				if rr.Code != tc.wantCode {
					t.Fatalf("expected %d, got %d", tc.wantCode, rr.Code)
				}
				env := decodeAuthErrorEnvelope(t, rr)
				if env.Error == nil || env.Error.Code != tc.wantErr {
					t.Fatalf("expected error code %q, got %+v", tc.wantErr, env.Error)
				}
			})
		}
	})

	t.Run("success clears auth cookies", func(t *testing.T) {
		authSvc := &stubAuthService{
			parseUserIDFn: func(subject string) (uint, error) { return 42, nil },
			changePassFn:  func(userID uint, currentPassword, newPassword string) error { return nil },
		}
		h := NewAuthHandler(authSvc, &stubAuthAbuseGuard{}, cookieMgr, nil, "state", 24*time.Hour)
		req := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/change", strings.NewReader(`{"current_password":"old","new_password":"new"}`)), "42")
		rr := httptest.NewRecorder()

		h.LocalChangePassword(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		cookies := rr.Result().Cookies()
		for _, name := range []string{"access_token", "refresh_token", "csrf_token", "oauth_state"} {
			if !isClearedCookie(cookies, name) {
				t.Fatalf("expected cleared cookie %q", name)
			}
		}
	})
}

func TestAuthHandlerBypassAndLocalFlowErrorMappings(t *testing.T) {
	cookieMgr := security.NewCookieManager("", false, "lax")

	t.Run("local login bypass trusted subnet skips abuse guard check", func(t *testing.T) {
		abuse := &stubAuthAbuseGuard{}
		authSvc := &stubAuthService{loginLocalFn: func(email, password, ua, ip string) (*service.LoginResult, error) {
			return &service.LoginResult{User: &domain.User{ID: 1}, AccessToken: "a", RefreshToken: "r", CSRFToken: "c", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}}
		h := NewAuthHandler(authSvc, abuse, cookieMgr, func(r *http.Request) (bool, string) {
			return true, "trusted_subnet"
		}, "state", 24*time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"u@example.com","password":"StrongPass123!"}`))
		rr := httptest.NewRecorder()

		h.LocalLogin(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if abuse.checkCalls != 0 {
			t.Fatalf("expected abuse check to be bypassed, got %d calls", abuse.checkCalls)
		}
	})

	t.Run("local login fallback uses abuse guard and can rate limit", func(t *testing.T) {
		abuse := &stubAuthAbuseGuard{checkFn: func(ctx context.Context, scope service.AuthAbuseScope, identity, ip string) (time.Duration, error) {
			return 5 * time.Second, nil
		}}
		h := NewAuthHandler(&stubAuthService{}, abuse, cookieMgr, nil, "state", 24*time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"u@example.com","password":"bad"}`))
		rr := httptest.NewRecorder()

		h.LocalLogin(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d", rr.Code)
		}
		if abuse.checkCalls != 1 {
			t.Fatalf("expected abuse check call, got %d", abuse.checkCalls)
		}
	})

	t.Run("password forgot bypass trusted actor skips abuse guard", func(t *testing.T) {
		abuse := &stubAuthAbuseGuard{}
		authSvc := &stubAuthService{forgotFn: func(email string) error { return nil }}
		h := NewAuthHandler(authSvc, abuse, cookieMgr, func(r *http.Request) (bool, string) { return true, "trusted_actor" }, "state", 24*time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/forgot", strings.NewReader(`{"email":"u@example.com"}`))
		rr := httptest.NewRecorder()

		h.LocalPasswordForgot(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if abuse.checkCalls != 0 {
			t.Fatalf("expected no abuse check when bypassed, got %d", abuse.checkCalls)
		}
	})

	t.Run("verify/forgot/reset payload and service mapping", func(t *testing.T) {
		h := NewAuthHandler(&stubAuthService{}, &stubAuthAbuseGuard{}, cookieMgr, nil, "state", 24*time.Hour)

		invalidJSON := bytes.NewBufferString(`{"email":`)
		rr := httptest.NewRecorder()
		h.LocalVerifyRequest(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify/request", invalidJSON))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("verify request invalid payload: expected 400, got %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		h.LocalVerifyConfirm(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify/confirm", bytes.NewBufferString(`{"token":`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("verify confirm invalid payload: expected 400, got %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		h.LocalPasswordForgot(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/forgot", bytes.NewBufferString(`{"email":`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("forgot invalid payload: expected 400, got %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		h.LocalPasswordReset(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", bytes.NewBufferString(`{"token":`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("reset invalid payload: expected 400, got %d", rr.Code)
		}
	})

	t.Run("verify/forgot/reset service classification", func(t *testing.T) {
		authSvc := &stubAuthService{
			requestVerifyFn: func(email string) error { return service.ErrLocalAuthDisabled },
			confirmVerifyFn: func(token string) error { return service.ErrInvalidVerifyToken },
			forgotFn:        func(email string) error { return service.ErrLocalAuthDisabled },
			resetFn:         func(token, newPassword string) error { return service.ErrWeakPassword },
		}
		h := NewAuthHandler(authSvc, &stubAuthAbuseGuard{}, cookieMgr, nil, "state", 24*time.Hour)

		rr := httptest.NewRecorder()
		h.LocalVerifyRequest(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify/request", strings.NewReader(`{"email":"u@example.com"}`)))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("verify request expected 404, got %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		h.LocalVerifyConfirm(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify/confirm", strings.NewReader(`{"token":"x"}`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("verify confirm expected 400, got %d", rr.Code)
		}
		env := decodeAuthErrorEnvelope(t, rr)
		if env.Error == nil || env.Error.Code != "INVALID_OR_EXPIRED_TOKEN" {
			t.Fatalf("expected INVALID_OR_EXPIRED_TOKEN, got %+v", env.Error)
		}

		rr = httptest.NewRecorder()
		h.LocalPasswordForgot(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/forgot", strings.NewReader(`{"email":"u@example.com"}`)))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("forgot expected 404, got %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		h.LocalPasswordReset(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", strings.NewReader(`{"token":"x","new_password":"weak"}`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("reset expected 400, got %d", rr.Code)
		}
	})
}

func TestAuthHandlerRefreshAndLogoutCookieSideEffects(t *testing.T) {
	cookieMgr := security.NewCookieManager("", false, "lax")

	t.Run("refresh success sets token cookies", func(t *testing.T) {
		authSvc := &stubAuthService{refreshFn: func(refreshToken, ua, ip string) (*service.LoginResult, error) {
			return &service.LoginResult{
				User:         &domain.User{ID: 9},
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				CSRFToken:    "new-csrf",
				ExpiresAt:    time.Now().Add(time.Hour),
			}, nil
		}}
		h := NewAuthHandler(authSvc, &stubAuthAbuseGuard{}, cookieMgr, nil, "state", 24*time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "old-refresh"})
		rr := httptest.NewRecorder()

		h.Refresh(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		cookies := rr.Result().Cookies()
		for _, name := range []string{"access_token", "refresh_token", "csrf_token"} {
			if !hasCookie(cookies, name) {
				t.Fatalf("expected cookie %q to be set", name)
			}
		}
	})

	t.Run("logout success clears cookies", func(t *testing.T) {
		authSvc := &stubAuthService{
			parseUserIDFn: func(subject string) (uint, error) { return 55, nil },
			logoutFn:      func(userID uint) error { return nil },
		}
		h := NewAuthHandler(authSvc, &stubAuthAbuseGuard{}, cookieMgr, nil, "state", 24*time.Hour)
		req := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil), "55")
		rr := httptest.NewRecorder()

		h.Logout(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		cookies := rr.Result().Cookies()
		for _, name := range []string{"access_token", "refresh_token", "csrf_token", "oauth_state"} {
			if !isClearedCookie(cookies, name) {
				t.Fatalf("expected cookie %q to be cleared", name)
			}
		}
	})
}
