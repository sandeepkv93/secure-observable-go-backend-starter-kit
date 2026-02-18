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
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
	servicegomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/service/gomock"
	"go.uber.org/mock/gomock"
)

func productAccessTokenForTest(t *testing.T, perms []string) string {
	t.Helper()
	jwt := security.NewJWTManager("iss", "aud", "abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnopqrstuvwxyz654321")
	tok, err := jwt.SignAccessToken(42, []string{"admin"}, perms, time.Hour)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}

func TestProductHandlerPaginationAndRBAC(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := servicegomock.NewMockProductService(ctrl)
	h := NewProductHandler(svc)
	jwt := security.NewJWTManager("iss", "aud", "abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnopqrstuvwxyz654321")
	rbac := service.NewRBACService()

	r := chi.NewRouter()
	r.Use(middleware.AuthMiddleware(jwt))
	r.Route("/api/v1/products", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequirePermission(rbac, nil, "products:read"))
			r.Get("/", h.List)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequirePermission(rbac, nil, "products:write"))
			r.Post("/", h.Create)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequirePermission(rbac, nil, "products:delete"))
			r.Delete("/{id}", h.Delete)
		})
	})

	t.Run("list uses pagination defaults", func(t *testing.T) {
		svc.EXPECT().ListPaged(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, req repository.PageRequest) (repository.PageResult[domain.Product], error) {
			if req.Page != repository.DefaultPage || req.PageSize != repository.DefaultPageSize {
				t.Fatalf("expected default pagination page=%d size=%d, got %+v", repository.DefaultPage, repository.DefaultPageSize, req)
			}
			return repository.PageResult[domain.Product]{Items: []domain.Product{{ID: 1, Name: "P", Price: 1.2}}, Page: req.Page, PageSize: req.PageSize, Total: 1, TotalPages: 1}, nil
		})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
		req.Header.Set("Authorization", "Bearer "+productAccessTokenForTest(t, []string{"products:read"}))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		var env map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
	})

	t.Run("write denied without products:write", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/products", strings.NewReader(`{"name":"Demo Product","price":10}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+productAccessTokenForTest(t, []string{"products:read"}))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("delete denied without products:delete", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/products/10", nil)
		req.Header.Set("Authorization", "Bearer "+productAccessTokenForTest(t, []string{"products:write"}))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("write allowed with products:write", func(t *testing.T) {
		svc.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, input service.CreateProductInput) (*domain.Product, error) {
			return &domain.Product{ID: 9, Name: input.Name, Description: input.Description, Price: input.Price}, nil
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/products", strings.NewReader(`{"name":"Demo Product","price":10}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+productAccessTokenForTest(t, []string{"products:write"}))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("delete rejects malformed product id", func(t *testing.T) {
		svc.EXPECT().DeleteByID(gomock.Any(), gomock.Any()).Times(0)
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/products/12abc", nil)
		req.Header.Set("Authorization", "Bearer "+productAccessTokenForTest(t, []string{"products:delete"}))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}
