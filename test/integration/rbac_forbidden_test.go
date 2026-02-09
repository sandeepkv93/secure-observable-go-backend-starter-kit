package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

func TestRBACForbiddenWithoutPermission(t *testing.T) {
	mgr := security.NewJWTManager("iss", "aud", "abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnopqrstuvwxyz654321")
	rbac := service.NewRBACService()
	token, err := mgr.SignAccessToken(1, []string{"user"}, []string{"users:read"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.With(middleware.AuthMiddleware(mgr), middleware.RequirePermission(rbac, "roles:write")).Post("/admin/roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/roles", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 got %d", w.Code)
	}
}
