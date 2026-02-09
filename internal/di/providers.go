package di

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/wire"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/app"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/database"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/health"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/handler"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/router"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

var ConfigSet = wire.NewSet(config.Load)

var ObservabilitySet = wire.NewSet(
	provideObservabilityRuntime,
	provideAppLogger,
)

var RuntimeInfraSet = wire.NewSet(
	provideRuntimeDB,
	provideRedisClient,
	provideReadinessProbeRunner,
)

var RepositorySet = wire.NewSet(
	repository.NewUserRepository,
	repository.NewRoleRepository,
	repository.NewPermissionRepository,
	repository.NewSessionRepository,
	repository.NewOAuthRepository,
	repository.NewLocalCredentialRepository,
	repository.NewVerificationTokenRepository,
)

var SecuritySet = wire.NewSet(
	provideJWTManager,
	provideCookieManager,
)

var ServiceSet = wire.NewSet(
	service.NewRBACService,
	service.NewUserService,
	provideSessionService,
	provideTokenService,
	service.NewGoogleOAuthProvider,
	service.NewDevEmailVerificationNotifier,
	wire.Bind(new(service.EmailVerificationNotifier), new(*service.DevEmailVerificationNotifier)),
	wire.Bind(new(service.PasswordResetNotifier), new(*service.DevEmailVerificationNotifier)),
	wire.Bind(new(service.OAuthProvider), new(*service.GoogleOAuthProvider)),
	service.NewOAuthService,
	service.NewAuthService,
	wire.Bind(new(service.UserServiceInterface), new(*service.UserService)),
	wire.Bind(new(service.SessionServiceInterface), new(*service.SessionService)),
	wire.Bind(new(service.AuthServiceInterface), new(*service.AuthService)),
	wire.Bind(new(service.RBACAuthorizer), new(*service.RBACService)),
)

var HTTPSet = wire.NewSet(
	provideAuthHandler,
	handler.NewUserHandler,
	handler.NewAdminHandler,
	provideGlobalRateLimiter,
	provideAuthRateLimiter,
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

func provideRedisClient(cfg *config.Config) redis.UniversalClient {
	if !cfg.RateLimitRedisEnabled {
		return nil
	}
	return redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
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

func provideSessionService(cfg *config.Config, sessionRepo repository.SessionRepository) *service.SessionService {
	return service.NewSessionService(sessionRepo, cfg.RefreshTokenPepper)
}

func provideAuthHandler(authSvc service.AuthServiceInterface, cookieMgr *security.CookieManager, cfg *config.Config) *handler.AuthHandler {
	return handler.NewAuthHandler(authSvc, cookieMgr, cfg.StateSigningSecret, cfg.JWTRefreshTTL)
}

func provideGlobalRateLimiter(cfg *config.Config, redisClient redis.UniversalClient) router.GlobalRateLimiterFunc {
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, cfg.RateLimitRedisPrefix+":api")
		return middleware.NewDistributedRateLimiter(
			redisLimiter,
			cfg.APIRateLimitPerMin,
			time.Minute,
			middleware.FailOpen,
			"api",
		).Middleware()
	}
	return middleware.NewRateLimiter(cfg.APIRateLimitPerMin, time.Minute).Middleware()
}

func provideAuthRateLimiter(cfg *config.Config, redisClient redis.UniversalClient) router.AuthRateLimiterFunc {
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, cfg.RateLimitRedisPrefix+":auth")
		return middleware.NewDistributedRateLimiter(
			redisLimiter,
			cfg.AuthRateLimitPerMin,
			time.Minute,
			middleware.FailClosed,
			"auth",
		).Middleware()
	}
	return middleware.NewRateLimiter(cfg.AuthRateLimitPerMin, time.Minute).Middleware()
}

func provideRouterDependencies(
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	adminHandler *handler.AdminHandler,
	jwt *security.JWTManager,
	rbac service.RBACAuthorizer,
	globalRateLimiter router.GlobalRateLimiterFunc,
	authRateLimiter router.AuthRateLimiterFunc,
	readiness *health.ProbeRunner,
	cfg *config.Config,
) router.Dependencies {
	return router.Dependencies{
		AuthHandler:                authHandler,
		UserHandler:                userHandler,
		AdminHandler:               adminHandler,
		JWTManager:                 jwt,
		RBACService:                rbac,
		CORSOrigins:                cfg.CORSAllowedOrigins,
		AuthRateLimitRPM:           cfg.AuthRateLimitPerMin,
		PasswordForgotRateLimitRPM: cfg.AuthPasswordForgotRateLimitPerMin,
		APIRateLimitRPM:            cfg.APIRateLimitPerMin,
		GlobalRateLimiter:          globalRateLimiter,
		AuthRateLimiter:            authRateLimiter,
		Readiness:                  readiness,
		EnableOTelHTTP:             cfg.OTELMetricsEnabled || cfg.OTELTracingEnabled,
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

func provideReadinessProbeRunner(cfg *config.Config, db *gorm.DB, redisClient redis.UniversalClient) *health.ProbeRunner {
	checkers := make([]health.Checker, 0, 2)
	if c := health.NewDBChecker(db); c != nil {
		checkers = append(checkers, c)
	}
	if cfg.RateLimitRedisEnabled {
		if c := health.NewRedisChecker(redisClient); c != nil {
			checkers = append(checkers, c)
		}
	}
	return health.NewProbeRunner(cfg.ReadinessProbeTimeout, cfg.ServerStartGracePeriod, checkers...)
}

func provideApp(
	cfg *config.Config,
	logger *slog.Logger,
	server *http.Server,
	runtime *observability.Runtime,
	db *gorm.DB,
	redisClient redis.UniversalClient,
	readiness *health.ProbeRunner,
) *app.App {
	return app.New(cfg, logger, server, runtime, db, redisClient, readiness)
}
