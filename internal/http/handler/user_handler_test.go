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
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

type stubUserSvc struct {
	getByIDFn func(id uint) (*domain.User, []string, error)
}

func (s *stubUserSvc) GetByID(id uint) (*domain.User, []string, error) {
	if s.getByIDFn != nil {
		return s.getByIDFn(id)
	}
	return nil, nil, errors.New("not implemented")
}

func (s *stubUserSvc) List() ([]domain.User, error) {
	return nil, errors.New("not implemented")
}

func (s *stubUserSvc) SetRoles(userID uint, roleIDs []uint) error {
	return errors.New("not implemented")
}

type stubSessionSvc struct {
	resolveFn func(r *http.Request, claims *security.Claims, userID uint) (uint, error)
	listFn    func(userID uint, currentSessionID uint) ([]service.SessionView, error)
	revokeFn  func(userID, sessionID uint) (string, error)
	revokeAll func(userID, currentSessionID uint) (int64, error)
}

func (s *stubSessionSvc) ListActiveSessions(userID uint, currentSessionID uint) ([]service.SessionView, error) {
	if s.listFn != nil {
		return s.listFn(userID, currentSessionID)
	}
	return nil, nil
}

func (s *stubSessionSvc) ResolveCurrentSessionID(r *http.Request, claims *security.Claims, userID uint) (uint, error) {
	if s.resolveFn != nil {
		return s.resolveFn(r, claims, userID)
	}
	return 0, nil
}

func (s *stubSessionSvc) RevokeSession(userID, sessionID uint) (string, error) {
	if s.revokeFn != nil {
		return s.revokeFn(userID, sessionID)
	}
	return "revoked", nil
}

func (s *stubSessionSvc) RevokeOtherSessions(userID, currentSessionID uint) (int64, error) {
	if s.revokeAll != nil {
		return s.revokeAll(userID, currentSessionID)
	}
	return 0, nil
}

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

func decodeUserErrCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var env map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	errObj, _ := env["error"].(map[string]any)
	code, _ := errObj["code"].(string)
	return code
}

func TestUserHandlerMeErrorMapping(t *testing.T) {
	h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	rr := httptest.NewRecorder()
	h.Me(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	h = NewUserHandler(&stubUserSvc{getByIDFn: func(id uint) (*domain.User, []string, error) {
		return nil, nil, errors.New("db down")
	}}, &stubSessionSvc{})
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
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{
			resolveFn: func(r *http.Request, claims *security.Claims, userID uint) (uint, error) {
				return 0, repository.ErrSessionNotFound
			},
			listFn: func(userID uint, currentSessionID uint) ([]service.SessionView, error) {
				called = true
				if currentSessionID != 0 {
					t.Fatalf("expected currentSessionID=0 on fallback, got %d", currentSessionID)
				}
				return []service.SessionView{{ID: 1}}, nil
			},
		})
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
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{
			resolveFn: func(r *http.Request, claims *security.Claims, userID uint) (uint, error) {
				return 0, errors.New("backend failed")
			},
		})
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
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{})
		req := withURLParam(baseReq.Clone(baseReq.Context()), "session_id", "not-a-number")
		rr := httptest.NewRecorder()
		h.RevokeSession(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("not found", func(t *testing.T) {
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{revokeFn: func(userID, sessionID uint) (string, error) {
			return "", repository.ErrSessionNotFound
		}})
		req := withURLParam(baseReq.Clone(baseReq.Context()), "session_id", "123")
		rr := httptest.NewRecorder()
		h.RevokeSession(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})

	t.Run("already revoked", func(t *testing.T) {
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{revokeFn: func(userID, sessionID uint) (string, error) {
			return "already_revoked", nil
		}})
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
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{revokeFn: func(userID, sessionID uint) (string, error) {
			if userID != 11 || sessionID != 123 {
				t.Fatalf("unexpected args userID=%d sessionID=%d", userID, sessionID)
			}
			return "revoked", nil
		}})
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
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{})
		rr := httptest.NewRecorder()
		h.RevokeOtherSessions(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke-others", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("resolve error", func(t *testing.T) {
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{resolveFn: func(r *http.Request, claims *security.Claims, userID uint) (uint, error) {
			return 0, errors.New("cannot resolve")
		}})
		rr := httptest.NewRecorder()
		h.RevokeOtherSessions(rr, userReqWithClaims(httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke-others", nil), "12"))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("internal error", func(t *testing.T) {
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{
			resolveFn: func(r *http.Request, claims *security.Claims, userID uint) (uint, error) { return 999, nil },
			revokeAll: func(userID, currentSessionID uint) (int64, error) {
				return 0, errors.New("db error")
			},
		})
		rr := httptest.NewRecorder()
		h.RevokeOtherSessions(rr, userReqWithClaims(httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke-others", nil), "12"))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rr.Code)
		}
	})

	t.Run("success", func(t *testing.T) {
		h := NewUserHandler(&stubUserSvc{}, &stubSessionSvc{
			resolveFn: func(r *http.Request, claims *security.Claims, userID uint) (uint, error) { return 444, nil },
			revokeAll: func(userID, currentSessionID uint) (int64, error) {
				if userID != 12 || currentSessionID != 444 {
					t.Fatalf("unexpected args userID=%d currentSessionID=%d", userID, currentSessionID)
				}
				return 3, nil
			},
		})
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
