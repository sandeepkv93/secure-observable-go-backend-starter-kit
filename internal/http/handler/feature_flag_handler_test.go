package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
)

type stubFeatureFlagService struct {
	evaluateAllFn func(ctx context.Context, evalCtx service.FeatureFlagEvaluationContext) ([]service.FeatureFlagEvaluationResult, error)
	evaluateByKey func(ctx context.Context, key string, evalCtx service.FeatureFlagEvaluationContext) (*service.FeatureFlagEvaluationResult, error)
	createFlagFn  func(ctx context.Context, flag *domain.FeatureFlag) error
}

func (s *stubFeatureFlagService) EvaluateAll(ctx context.Context, evalCtx service.FeatureFlagEvaluationContext) ([]service.FeatureFlagEvaluationResult, error) {
	if s.evaluateAllFn != nil {
		return s.evaluateAllFn(ctx, evalCtx)
	}
	return nil, nil
}

func (s *stubFeatureFlagService) EvaluateByKey(ctx context.Context, key string, evalCtx service.FeatureFlagEvaluationContext) (*service.FeatureFlagEvaluationResult, error) {
	if s.evaluateByKey != nil {
		return s.evaluateByKey(ctx, key, evalCtx)
	}
	return &service.FeatureFlagEvaluationResult{Key: key}, nil
}

func (s *stubFeatureFlagService) ListFlags(context.Context) ([]domain.FeatureFlag, error) {
	return nil, nil
}
func (s *stubFeatureFlagService) GetFlagByID(context.Context, uint) (*domain.FeatureFlag, error) {
	return &domain.FeatureFlag{}, nil
}
func (s *stubFeatureFlagService) CreateFlag(ctx context.Context, flag *domain.FeatureFlag) error {
	if s.createFlagFn != nil {
		return s.createFlagFn(ctx, flag)
	}
	return nil
}
func (s *stubFeatureFlagService) UpdateFlag(context.Context, *domain.FeatureFlag) error { return nil }
func (s *stubFeatureFlagService) DeleteFlag(context.Context, uint) error                { return nil }
func (s *stubFeatureFlagService) ListRules(context.Context, uint) ([]domain.FeatureFlagRule, error) {
	return nil, nil
}
func (s *stubFeatureFlagService) CreateRule(context.Context, *domain.FeatureFlagRule) error {
	return nil
}
func (s *stubFeatureFlagService) UpdateRule(context.Context, *domain.FeatureFlagRule) error {
	return nil
}
func (s *stubFeatureFlagService) DeleteRule(context.Context, uint, uint) error { return nil }

func accessTokenForTest(t *testing.T, perms []string) string {
	t.Helper()
	jwt := security.NewJWTManager("iss", "aud", "abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnopqrstuvwxyz654321")
	tok, err := jwt.SignAccessToken(42, []string{"admin"}, perms, time.Hour)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}

func TestFeatureFlagHandlerEvaluateAndAdminRBAC(t *testing.T) {
	svc := &stubFeatureFlagService{}
	h := NewFeatureFlagHandler(svc)
	jwt := security.NewJWTManager("iss", "aud", "abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnopqrstuvwxyz654321")
	rbac := service.NewRBACService()

	r := chi.NewRouter()
	r.Use(middleware.AuthMiddleware(jwt))
	r.Get("/api/v1/feature-flags", h.EvaluateAll)
	r.With(middleware.RequirePermission(rbac, nil, "feature_flags:write")).Post("/api/v1/admin/feature-flags", h.CreateFlag)

	t.Run("user evaluation succeeds with auth", func(t *testing.T) {
		svc.evaluateAllFn = func(ctx context.Context, evalCtx service.FeatureFlagEvaluationContext) ([]service.FeatureFlagEvaluationResult, error) {
			if evalCtx.UserID != 42 {
				t.Fatalf("expected user id 42, got %d", evalCtx.UserID)
			}
			return []service.FeatureFlagEvaluationResult{{Key: "new_checkout", Enabled: true, Source: "default"}}, nil
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/feature-flags?environment=dev", nil)
		req.Header.Set("Authorization", "Bearer "+accessTokenForTest(t, []string{"users:read"}))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("admin create denied without permission", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/feature-flags", strings.NewReader(`{"key":"new_checkout","enabled":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessTokenForTest(t, []string{"users:read"}))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("admin create allowed with permission", func(t *testing.T) {
		called := false
		svc.createFlagFn = func(ctx context.Context, flag *domain.FeatureFlag) error {
			called = true
			flag.ID = 99
			return nil
		}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/feature-flags", strings.NewReader(`{"key":"new_checkout","enabled":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessTokenForTest(t, []string{"feature_flags:write"}))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d body=%s", rr.Code, rr.Body.String())
		}
		if !called {
			t.Fatal("expected create flag service call")
		}
		var envelope map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
	})
}

func TestFeatureFlagHandlerGetFlagRejectsMalformedID(t *testing.T) {
	svc := &stubFeatureFlagService{}
	h := NewFeatureFlagHandler(svc)

	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/v1/admin/feature-flags/12abc", nil), "id", "12abc")
	rr := httptest.NewRecorder()
	h.GetFlag(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
}
