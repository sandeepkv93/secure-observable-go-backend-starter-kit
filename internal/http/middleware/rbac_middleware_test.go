package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	servicegomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/service/gomock"
	"go.uber.org/mock/gomock"
)

func TestRequirePermissionDenied(t *testing.T) {
	ctrl := gomock.NewController(t)
	authorizer := servicegomock.NewMockRBACAuthorizer(ctrl)
	authorizer.EXPECT().HasPermission([]string{"user:read"}, "admin:read").Return(false)
	mw := RequirePermission(authorizer, nil, "admin:read")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ClaimsContextKey, &security.Claims{Permissions: []string{"user:read"}}))
	rr := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected middleware to block request")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

func TestRequirePermissionResolverError(t *testing.T) {
	resolverErr := errors.New("resolver unavailable")
	ctrl := gomock.NewController(t)
	authorizer := servicegomock.NewMockRBACAuthorizer(ctrl)
	resolver := servicegomock.NewMockPermissionResolver(ctrl)
	resolver.EXPECT().ResolvePermissions(gomock.Any(), gomock.Any()).Return(nil, resolverErr)
	authorizer.EXPECT().HasPermission(gomock.Any(), "admin:read").Times(0)
	mw := RequirePermission(authorizer, resolver, "admin:read")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ClaimsContextKey, &security.Claims{Permissions: []string{"admin:read"}}))
	rr := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expected middleware to block request")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rr.Code)
	}
}

func TestRequirePermissionAllowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	authorizer := servicegomock.NewMockRBACAuthorizer(ctrl)
	resolver := servicegomock.NewMockPermissionResolver(ctrl)
	resolver.EXPECT().ResolvePermissions(gomock.Any(), gomock.Any()).Return([]string{"admin:read"}, nil)
	authorizer.EXPECT().HasPermission([]string{"admin:read"}, "admin:read").Return(true)
	mw := RequirePermission(authorizer, resolver, "admin:read")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ClaimsContextKey, &security.Claims{Permissions: []string{"admin:read"}}))
	rr := httptest.NewRecorder()

	called := false
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if !called {
		t.Fatal("expected wrapped handler to be called")
	}
}
