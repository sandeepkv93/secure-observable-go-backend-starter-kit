package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
	servicegomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/service/gomock"
	"go.uber.org/mock/gomock"
)

func userReqWithClaims(r *http.Request, sub string) *http.Request {
	claims := &security.Claims{}
	claims.Subject = sub
	ctx := context.WithValue(r.Context(), middleware.ClaimsContextKey, claims)
	return r.WithContext(ctx)
}

func withURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	return r.WithContext(ctx)
}

func TestUserHandlerMeErrorMapping(t *testing.T) {
	ctrl := gomock.NewController(t)
	userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
	sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
	storageSvc := servicegomock.NewMockStorageService(ctrl)
	h := NewUserHandler(userSvc, sessionSvc, storageSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	rr := httptest.NewRecorder()
	h.Me(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	userSvc.EXPECT().GetByID(uint(7)).Return(nil, nil, errors.New("db down"))
	h = NewUserHandler(userSvc, sessionSvc, storageSvc)
	req = userReqWithClaims(httptest.NewRequest(http.MethodGet, "/api/v1/me", nil), "7")
	rr = httptest.NewRecorder()
	h.Me(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestUserHandlerSessionsResolveFallbackAndErrors(t *testing.T) {
	t.Run("resolve ErrSessionNotFound falls back to list with current_session_id=0", func(t *testing.T) {
		called := false
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		sessionSvc.EXPECT().ResolveCurrentSessionID(gomock.Any(), gomock.Any(), uint(9)).Return(uint(0), repository.ErrSessionNotFound)
		sessionSvc.EXPECT().ListActiveSessions(uint(9), uint(0)).DoAndReturn(func(userID uint, currentSessionID uint) ([]service.SessionView, error) {
			called = true
			if currentSessionID != 0 {
				t.Fatalf("expected currentSessionID=0 on fallback, got %d", currentSessionID)
			}
			return []service.SessionView{{ID: 1}}, nil
		})
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		req := userReqWithClaims(httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil), "9")
		rr := httptest.NewRecorder()

		h.Sessions(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if !called {
			t.Fatal("expected list to be called")
		}
	})

	t.Run("resolve generic error returns 500", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		sessionSvc.EXPECT().ResolveCurrentSessionID(gomock.Any(), gomock.Any(), uint(9)).Return(uint(0), errors.New("backend failed"))
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		req := userReqWithClaims(httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil), "9")
		rr := httptest.NewRecorder()

		h.Sessions(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rr.Code)
		}
	})
}

func TestUserHandlerRevokeSessionMatrix(t *testing.T) {
	baseReq := userReqWithClaims(httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/1", nil), "11")

	t.Run("invalid session id", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		sessionSvc.EXPECT().RevokeSession(gomock.Any(), gomock.Any()).Times(0)
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		req := withURLParam(baseReq.Clone(baseReq.Context()), "session_id", "not-a-number")
		rr := httptest.NewRecorder()
		h.RevokeSession(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		sessionSvc.EXPECT().RevokeSession(uint(11), uint(123)).Return("", repository.ErrSessionNotFound)
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		req := withURLParam(baseReq.Clone(baseReq.Context()), "session_id", "123")
		rr := httptest.NewRecorder()
		h.RevokeSession(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})

	t.Run("already revoked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		sessionSvc.EXPECT().RevokeSession(uint(11), uint(123)).Return("already_revoked", nil)
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		req := withURLParam(baseReq.Clone(baseReq.Context()), "session_id", "123")
		rr := httptest.NewRecorder()
		h.RevokeSession(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "already_revoked") {
			t.Fatalf("expected already_revoked in body, got %s", rr.Body.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		sessionSvc.EXPECT().RevokeSession(uint(11), uint(123)).Return("revoked", nil)
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		req := withURLParam(baseReq.Clone(baseReq.Context()), "session_id", strconv.Itoa(123))
		rr := httptest.NewRecorder()
		h.RevokeSession(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
	})
}

func TestUserHandlerRevokeOtherSessionsMatrix(t *testing.T) {
	t.Run("unauthorized missing claims", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		rr := httptest.NewRecorder()
		h.RevokeOtherSessions(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke-others", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("resolve error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		sessionSvc.EXPECT().ResolveCurrentSessionID(gomock.Any(), gomock.Any(), uint(12)).Return(uint(0), errors.New("cannot resolve"))
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		rr := httptest.NewRecorder()
		h.RevokeOtherSessions(rr, userReqWithClaims(httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke-others", nil), "12"))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("internal error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		sessionSvc.EXPECT().ResolveCurrentSessionID(gomock.Any(), gomock.Any(), uint(12)).Return(uint(999), nil)
		sessionSvc.EXPECT().RevokeOtherSessions(uint(12), uint(999)).Return(int64(0), errors.New("db error"))
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		rr := httptest.NewRecorder()
		h.RevokeOtherSessions(rr, userReqWithClaims(httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke-others", nil), "12"))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rr.Code)
		}
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		userSvc := servicegomock.NewMockUserServiceInterface(ctrl)
		sessionSvc := servicegomock.NewMockSessionServiceInterface(ctrl)
		storageSvc := servicegomock.NewMockStorageService(ctrl)
		sessionSvc.EXPECT().ResolveCurrentSessionID(gomock.Any(), gomock.Any(), uint(12)).Return(uint(444), nil)
		sessionSvc.EXPECT().RevokeOtherSessions(uint(12), uint(444)).Return(int64(3), nil)
		h := NewUserHandler(userSvc, sessionSvc, storageSvc)
		rr := httptest.NewRecorder()
		h.RevokeOtherSessions(rr, userReqWithClaims(httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke-others", nil), "12"))
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "revoked_count") {
			t.Fatalf("expected revoked_count in response body, got %s", rr.Body.String())
		}
	})
}

func TestAuthUserIDAndClaimsParseError(t *testing.T) {
	req := userReqWithClaims(httptest.NewRequest(http.MethodGet, "/", nil), "not-number")
	_, _, err := authUserIDAndClaims(req)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestSessionViewJSONShapeSmoke(t *testing.T) {
	views := []service.SessionView{{ID: 1, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}}
	b, err := json.Marshal(views)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("expected non-empty json")
	}
}
