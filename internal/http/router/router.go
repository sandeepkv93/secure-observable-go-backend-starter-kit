package router

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/handler"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

type Dependencies struct {
	AuthHandler       *handler.AuthHandler
	UserHandler       *handler.UserHandler
	AdminHandler      *handler.AdminHandler
	JWTManager        *security.JWTManager
	RBACService       service.RBACAuthorizer
	CORSOrigins       []string
	AuthRateLimitRPM  int
	APIRateLimitRPM   int
	GlobalRateLimiter GlobalRateLimiterFunc
	AuthRateLimiter   AuthRateLimiterFunc
	EnableOTelHTTP    bool
}

type GlobalRateLimiterFunc func(http.Handler) http.Handler
type AuthRateLimiterFunc func(http.Handler) http.Handler

func NewRouter(dep Dependencies) http.Handler {
	r := chi.NewRouter()
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.StructuredRequestLogger)
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.CORS(dep.CORSOrigins))
	r.Use(middleware.BodyLimit(1 << 20))
	if dep.GlobalRateLimiter != nil {
		r.Use(dep.GlobalRateLimiter)
	} else {
		r.Use(middleware.NewRateLimiter(dep.APIRateLimitRPM, time.Minute).Middleware())
	}

	authLimiter := dep.AuthRateLimiter
	if authLimiter == nil {
		authLimiter = middleware.NewRateLimiter(dep.AuthRateLimitRPM, time.Minute).Middleware()
	}

	r.Get("/health/live", func(w http.ResponseWriter, r *http.Request) {
		response.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		response.JSON(w, r, http.StatusOK, map[string]string{"status": "ready"})
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.With(authLimiter).Get("/google/login", dep.AuthHandler.GoogleLogin)
			r.With(authLimiter).Get("/google/callback", dep.AuthHandler.GoogleCallback)
			r.With(authLimiter).Post("/local/register", dep.AuthHandler.LocalRegister)
			r.With(authLimiter).Post("/local/login", dep.AuthHandler.LocalLogin)
			r.Group(func(r chi.Router) {
				r.Use(middleware.CSRFMiddleware)
				r.With(authLimiter).Post("/refresh", dep.AuthHandler.Refresh)
				r.With(middleware.AuthMiddleware(dep.JWTManager)).Post("/logout", dep.AuthHandler.Logout)
				r.With(middleware.AuthMiddleware(dep.JWTManager), authLimiter).Post("/local/change-password", dep.AuthHandler.LocalChangePassword)
			})
		})

		r.With(middleware.AuthMiddleware(dep.JWTManager)).Get("/me", dep.UserHandler.Me)

		r.Route("/admin", func(r chi.Router) {
			r.Use(middleware.AuthMiddleware(dep.JWTManager))
			r.With(middleware.RequirePermission(dep.RBACService, "users:read")).Get("/users", dep.AdminHandler.ListUsers)
			r.With(middleware.RequirePermission(dep.RBACService, "users:write")).Patch("/users/{id}/roles", dep.AdminHandler.SetUserRoles)
			r.With(middleware.RequirePermission(dep.RBACService, "roles:read")).Get("/roles", dep.AdminHandler.ListRoles)
			r.With(middleware.RequirePermission(dep.RBACService, "roles:write")).Post("/roles", dep.AdminHandler.CreateRole)
			r.With(middleware.RequirePermission(dep.RBACService, "permissions:read")).Get("/permissions", dep.AdminHandler.ListPermissions)
		})
	})

	var h http.Handler = r
	if dep.EnableOTelHTTP {
		h = otelhttp.NewHandler(r, "http.server")
	}
	return h
}
