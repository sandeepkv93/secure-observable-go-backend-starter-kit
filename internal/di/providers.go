package di

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/wire"
	"gorm.io/gorm"

	"go-oauth-rbac-service/internal/app"
	"go-oauth-rbac-service/internal/config"
	"go-oauth-rbac-service/internal/database"
	"go-oauth-rbac-service/internal/http/handler"
	"go-oauth-rbac-service/internal/http/router"
	"go-oauth-rbac-service/internal/observability"
	"go-oauth-rbac-service/internal/repository"
	"go-oauth-rbac-service/internal/security"
	"go-oauth-rbac-service/internal/service"
)

var ConfigSet = wire.NewSet(config.Load)

var ObservabilitySet = wire.NewSet(
	provideObservabilityRuntime,
	provideAppLogger,
)

var RuntimeInfraSet = wire.NewSet(
	provideRuntimeDB,
)

var RepositorySet = wire.NewSet(
	repository.NewUserRepository,
	repository.NewRoleRepository,
	repository.NewPermissionRepository,
	repository.NewSessionRepository,
	repository.NewOAuthRepository,
)

var SecuritySet = wire.NewSet(
	provideJWTManager,
	provideCookieManager,
)

var ServiceSet = wire.NewSet(
	service.NewRBACService,
	service.NewUserService,
	provideTokenService,
	service.NewGoogleOAuthProvider,
	wire.Bind(new(service.OAuthProvider), new(*service.GoogleOAuthProvider)),
	service.NewOAuthService,
	service.NewAuthService,
	wire.Bind(new(service.UserServiceInterface), new(*service.UserService)),
	wire.Bind(new(service.AuthServiceInterface), new(*service.AuthService)),
	wire.Bind(new(service.RBACAuthorizer), new(*service.RBACService)),
)

var HTTPSet = wire.NewSet(
	provideAuthHandler,
	handler.NewUserHandler,
	handler.NewAdminHandler,
	provideRouterDependencies,
	router.NewRouter,
	provideHTTPServer,
)

var AppSet = wire.NewSet(provideApp)

type MigrationRunner struct {
	cfg *config.Config
	db  *gorm.DB
}

func NewMigrationRunner(cfg *config.Config, db *gorm.DB) *MigrationRunner {
	return &MigrationRunner{cfg: cfg, db: db}
}

func (m *MigrationRunner) Run() error {
	if err := database.Migrate(m.db); err != nil {
		return err
	}
	if err := database.Seed(m.db, m.cfg.BootstrapAdminEmail); err != nil {
		return err
	}
	fmt.Println("migration complete")
	return nil
}

func provideObservabilityRuntime(cfg *config.Config) (*observability.Runtime, error) {
	bootstrapLogger := observability.NewBootstrapLogger(cfg)
	return observability.InitRuntime(context.Background(), cfg, bootstrapLogger)
}

func provideAppLogger(cfg *config.Config, runtime *observability.Runtime) *slog.Logger {
	return observability.InitLogger(cfg, runtime.LoggerProvider)
}

func provideOpenDB(cfg *config.Config) (*gorm.DB, error) {
	return database.Open(cfg)
}

func provideRuntimeDB(cfg *config.Config) (*gorm.DB, error) {
	db, err := database.Open(cfg)
	if err != nil {
		return nil, err
	}
	if err := database.Migrate(db); err != nil {
		return nil, err
	}
	if err := database.Seed(db, cfg.BootstrapAdminEmail); err != nil {
		return nil, err
	}
	return db, nil
}

func provideJWTManager(cfg *config.Config) *security.JWTManager {
	return security.NewJWTManager(cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTAccessSecret, cfg.JWTRefreshSecret)
}

func provideCookieManager(cfg *config.Config) *security.CookieManager {
	return security.NewCookieManager(cfg.CookieDomain, cfg.CookieSecure, cfg.CookieSameSite)
}

func provideTokenService(cfg *config.Config, jwt *security.JWTManager, sessionRepo repository.SessionRepository) *service.TokenService {
	return service.NewTokenService(jwt, sessionRepo, cfg.RefreshTokenPepper, cfg.JWTAccessTTL, cfg.JWTRefreshTTL)
}

func provideAuthHandler(authSvc service.AuthServiceInterface, cookieMgr *security.CookieManager, cfg *config.Config) *handler.AuthHandler {
	return handler.NewAuthHandler(authSvc, cookieMgr, cfg.StateSigningSecret, cfg.JWTRefreshTTL)
}

func provideRouterDependencies(
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	adminHandler *handler.AdminHandler,
	jwt *security.JWTManager,
	rbac service.RBACAuthorizer,
	cfg *config.Config,
) router.Dependencies {
	return router.Dependencies{
		AuthHandler:      authHandler,
		UserHandler:      userHandler,
		AdminHandler:     adminHandler,
		JWTManager:       jwt,
		RBACService:      rbac,
		CORSOrigins:      cfg.CORSAllowedOrigins,
		AuthRateLimitRPM: cfg.AuthRateLimitPerMin,
		APIRateLimitRPM:  cfg.APIRateLimitPerMin,
		EnableOTelHTTP:   cfg.OTELMetricsEnabled || cfg.OTELTracingEnabled,
	}
}

func provideHTTPServer(cfg *config.Config, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           h,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func provideApp(cfg *config.Config, logger *slog.Logger, server *http.Server, runtime *observability.Runtime) *app.App {
	return app.New(cfg, logger, server, runtime)
}
