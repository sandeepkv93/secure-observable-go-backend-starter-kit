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

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
	servicegomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/service/gomock"
	"go.uber.org/mock/gomock"
)

type authErrorEnvelope struct {
	Success bool `json:"success"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
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
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		h := NewAuthHandler(authSvc, abuse, cookieMgr, nil, "state", 24*time.Hour)
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
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		authSvc.EXPECT().ParseUserID("bad").Return(uint(0), errors.New("bad subject"))
		h := NewAuthHandler(authSvc, abuse, cookieMgr, nil, "state", 24*time.Hour)
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
				ctrl := gomock.NewController(t)
				authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
				abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
				authSvc.EXPECT().ParseUserID("77").Return(uint(77), nil)
				authSvc.EXPECT().ChangeLocalPassword(uint(77), "old", "new").Return(tc.err)
				h := NewAuthHandler(authSvc, abuse, cookieMgr, nil, "state", 24*time.Hour)
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
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		authSvc.EXPECT().ParseUserID("42").Return(uint(42), nil)
		authSvc.EXPECT().ChangeLocalPassword(uint(42), "old", "new").Return(nil)
		h := NewAuthHandler(authSvc, abuse, cookieMgr, nil, "state", 24*time.Hour)
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
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		abuse.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
		authSvc.EXPECT().LoginWithLocalPassword("u@example.com", "StrongPass123!", gomock.Any(), gomock.Any()).Return(
			&service.LoginResult{User: &domain.User{ID: 1}, AccessToken: "a", RefreshToken: "r", CSRFToken: "c", ExpiresAt: time.Now().Add(time.Hour)}, nil,
		)
		h := NewAuthHandler(authSvc, abuse, cookieMgr, func(r *http.Request) (bool, string) {
			return true, "trusted_subnet"
		}, "state", 24*time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"u@example.com","password":"StrongPass123!"}`))
		rr := httptest.NewRecorder()

		h.LocalLogin(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("local login fallback uses abuse guard and can rate limit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		abuse.EXPECT().Check(gomock.Any(), service.AuthAbuseScopeLogin, "u@example.com", gomock.Any()).Return(5*time.Second, nil)
		authSvc.EXPECT().LoginWithLocalPassword(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
		h := NewAuthHandler(authSvc, abuse, cookieMgr, nil, "state", 24*time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"u@example.com","password":"bad"}`))
		rr := httptest.NewRecorder()

		h.LocalLogin(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d", rr.Code)
		}
	})

	t.Run("password forgot bypass trusted actor skips abuse guard", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		abuse.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
		authSvc.EXPECT().ForgotLocalPassword("u@example.com").Return(nil)
		h := NewAuthHandler(authSvc, abuse, cookieMgr, func(r *http.Request) (bool, string) { return true, "trusted_actor" }, "state", 24*time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/forgot", strings.NewReader(`{"email":"u@example.com"}`))
		rr := httptest.NewRecorder()

		h.LocalPasswordForgot(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("verify/forgot/reset payload and service mapping", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		h := NewAuthHandler(authSvc, abuse, cookieMgr, nil, "state", 24*time.Hour)

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
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		abuse.EXPECT().Check(gomock.Any(), service.AuthAbuseScopeForgot, "u@example.com", gomock.Any()).Return(time.Duration(0), nil)
		authSvc.EXPECT().RequestLocalEmailVerification("u@example.com").Return(service.ErrLocalAuthDisabled)
		authSvc.EXPECT().ConfirmLocalEmailVerification("x").Return(service.ErrInvalidVerifyToken)
		authSvc.EXPECT().ForgotLocalPassword("u@example.com").Return(service.ErrLocalAuthDisabled)
		authSvc.EXPECT().ResetLocalPassword("x", "weak").Return(service.ErrWeakPassword)
		h := NewAuthHandler(authSvc, abuse, cookieMgr, nil, "state", 24*time.Hour)

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
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		authSvc.EXPECT().Refresh("old-refresh", gomock.Any(), gomock.Any()).Return(&service.LoginResult{
			User:         &domain.User{ID: 9},
			AccessToken:  "new-access",
			RefreshToken: "new-refresh",
			CSRFToken:    "new-csrf",
			ExpiresAt:    time.Now().Add(time.Hour),
		}, nil)
		h := NewAuthHandler(authSvc, abuse, cookieMgr, nil, "state", 24*time.Hour)
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
		ctrl := gomock.NewController(t)
		authSvc := servicegomock.NewMockAuthServiceInterface(ctrl)
		abuse := servicegomock.NewMockAuthAbuseGuard(ctrl)
		authSvc.EXPECT().ParseUserID("55").Return(uint(55), nil)
		authSvc.EXPECT().Logout(uint(55)).Return(nil)
		h := NewAuthHandler(authSvc, abuse, cookieMgr, nil, "state", 24*time.Hour)
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
