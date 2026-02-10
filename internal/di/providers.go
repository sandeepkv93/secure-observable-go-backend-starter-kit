package di

import (
	"context"
	"fmt"
	"log/slog"
	"math"
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
	provideAuthAbuseGuard,
	handler.NewUserHandler,
	provideRBACPermissionCacheStore,
	providePermissionResolver,
	provideAdminListCacheStore,
	provideNegativeLookupCacheStore,
	handler.NewAdminHandler,
	provideGlobalRateLimiter,
	provideAuthRateLimiter,
	provideForgotRateLimiter,
	provideRouteRateLimitPolicies,
	provideIdempotencyStore,
	provideIdempotencyMiddlewareFactory,
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
	if !cfg.RateLimitRedisEnabled &&
		!cfg.AuthAbuseProtectionEnabled &&
		(!cfg.IdempotencyEnabled || !cfg.IdempotencyRedisEnabled) &&
		!cfg.AdminListCacheEnabled &&
		!cfg.NegativeLookupCacheEnabled &&
		!cfg.RBACPermissionCacheEnabled {
		return nil
	}
	return redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
}

func provideRBACPermissionCacheStore(cfg *config.Config, redisClient redis.UniversalClient) service.RBACPermissionCacheStore {
	if !cfg.RBACPermissionCacheEnabled {
		return service.NewNoopRBACPermissionCacheStore()
	}
	if redisClient == nil {
		return service.NewNoopRBACPermissionCacheStore()
	}
	return service.NewRedisRBACPermissionCacheStore(redisClient, cfg.RBACPermissionCacheRedisPref)
}

func providePermissionResolver(cfg *config.Config, userSvc service.UserServiceInterface, store service.RBACPermissionCacheStore) service.PermissionResolver {
	return service.NewCachedPermissionResolver(store, userSvc, cfg.RBACPermissionCacheTTL)
}

func provideAdminListCacheStore(cfg *config.Config, redisClient redis.UniversalClient) service.AdminListCacheStore {
	if !cfg.AdminListCacheEnabled {
		return service.NewNoopAdminListCacheStore()
	}
	if redisClient == nil {
		return service.NewNoopAdminListCacheStore()
	}
	return service.NewRedisAdminListCacheStore(redisClient, cfg.AdminListCacheRedisPrefix)
}

func provideNegativeLookupCacheStore(cfg *config.Config, redisClient redis.UniversalClient) service.NegativeLookupCacheStore {
	if !cfg.NegativeLookupCacheEnabled {
		return service.NewNoopNegativeLookupCacheStore()
	}
	if redisClient == nil {
		return service.NewNoopNegativeLookupCacheStore()
	}
	return service.NewRedisNegativeLookupCacheStore(redisClient, cfg.NegativeLookupCacheRedisPref)
}

func provideIdempotencyStore(cfg *config.Config, db *gorm.DB, redisClient redis.UniversalClient) service.IdempotencyStore {
	if !cfg.IdempotencyEnabled {
		return nil
	}
	if cfg.IdempotencyRedisEnabled && redisClient != nil {
		return service.NewRedisIdempotencyStore(redisClient, cfg.IdempotencyRedisPrefix)
	}
	return service.NewDBIdempotencyStore(db)
}

func provideIdempotencyMiddlewareFactory(cfg *config.Config, store service.IdempotencyStore) router.IdempotencyMiddlewareFactory {
	if !cfg.IdempotencyEnabled || store == nil {
		return nil
	}
	mw := middleware.NewIdempotencyMiddleware(store, cfg.IdempotencyTTL)
	return func(scope string) func(http.Handler) http.Handler {
		return mw.Middleware(scope)
	}
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

func provideAuthAbuseGuard(cfg *config.Config, redisClient redis.UniversalClient) service.AuthAbuseGuard {
	if !cfg.AuthAbuseProtectionEnabled {
		return service.NewNoopAuthAbuseGuard()
	}
	policy := service.AuthAbusePolicy{
		FreeAttempts: cfg.AuthAbuseFreeAttempts,
		BaseDelay:    cfg.AuthAbuseBaseDelay,
		Multiplier:   cfg.AuthAbuseMultiplier,
		MaxDelay:     cfg.AuthAbuseMaxDelay,
		ResetWindow:  cfg.AuthAbuseResetWindow,
	}
	if redisClient != nil {
		return service.NewRedisAuthAbuseGuard(redisClient, cfg.AuthAbuseRedisPrefix, policy)
	}
	return service.NewInMemoryAuthAbuseGuard(policy)
}

func provideAuthHandler(
	authSvc service.AuthServiceInterface,
	abuseGuard service.AuthAbuseGuard,
	cookieMgr *security.CookieManager,
	cfg *config.Config,
) *handler.AuthHandler {
	return handler.NewAuthHandler(authSvc, abuseGuard, cookieMgr, cfg.StateSigningSecret, cfg.JWTRefreshTTL)
}

func provideGlobalRateLimiter(cfg *config.Config, redisClient redis.UniversalClient, jwt *security.JWTManager) router.GlobalRateLimiterFunc {
	keyFunc := middleware.SubjectOrIPKeyFunc(jwt)
	policy := toRateLimitPolicy(cfg.APIRateLimitPerMin, cfg)
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, cfg.RateLimitRedisPrefix+":api")
		return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
			redisLimiter,
			policy,
			middleware.FailOpen,
			"api",
			keyFunc,
		).Middleware()
	}
	return middleware.NewRateLimiterWithPolicy(policy, keyFunc).Middleware()
}

func provideAuthRateLimiter(cfg *config.Config, redisClient redis.UniversalClient) router.AuthRateLimiterFunc {
	policy := toRateLimitPolicy(cfg.AuthRateLimitPerMin, cfg)
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, cfg.RateLimitRedisPrefix+":auth")
		return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
			redisLimiter,
			policy,
			middleware.FailClosed,
			"auth",
			nil,
		).Middleware()
	}
	return middleware.NewRateLimiterWithPolicy(policy, nil).Middleware()
}

func provideForgotRateLimiter(cfg *config.Config, redisClient redis.UniversalClient) router.ForgotRateLimiterFunc {
	policy := toRateLimitPolicy(cfg.AuthPasswordForgotRateLimitPerMin, cfg)
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, cfg.RateLimitRedisPrefix+":auth:forgot")
		return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
			redisLimiter,
			policy,
			middleware.FailClosed,
			"auth_password_forgot",
			nil,
		).Middleware()
	}
	return middleware.NewRateLimiterWithPolicy(policy, nil).Middleware()
}

func provideRouteRateLimitPolicies(cfg *config.Config, redisClient redis.UniversalClient, jwt *security.JWTManager) router.RouteRateLimitPolicies {
	policies := make(router.RouteRateLimitPolicies, 4)
	policies[router.RoutePolicyLogin] = buildRoutePolicyLimiter(
		cfg,
		redisClient,
		"route:login",
		cfg.RateLimitLoginPerMin,
		middleware.FailClosed,
		"route_login",
		nil,
	)
	policies[router.RoutePolicyRefresh] = buildRoutePolicyLimiter(
		cfg,
		redisClient,
		"route:refresh",
		cfg.RateLimitRefreshPerMin,
		middleware.FailClosed,
		"route_refresh",
		middleware.SubjectOrIPKeyFunc(jwt),
	)
	subjectKey := middleware.SubjectOrIPKeyFunc(jwt)
	policies[router.RoutePolicyAdminWrite] = buildRoutePolicyLimiter(
		cfg,
		redisClient,
		"route:admin:write",
		cfg.RateLimitAdminWritePerMin,
		middleware.FailClosed,
		"route_admin_write",
		subjectKey,
	)
	policies[router.RoutePolicyAdminSync] = buildRoutePolicyLimiter(
		cfg,
		redisClient,
		"route:admin:sync",
		cfg.RateLimitAdminSyncPerMin,
		middleware.FailClosed,
		"route_admin_sync",
		subjectKey,
	)
	return policies
}

func buildRoutePolicyLimiter(
	cfg *config.Config,
	redisClient redis.UniversalClient,
	redisSuffix string,
	limit int,
	mode middleware.FailureMode,
	scope string,
	keyFunc func(*http.Request) string,
) func(http.Handler) http.Handler {
	policy := toRateLimitPolicy(limit, cfg)
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, cfg.RateLimitRedisPrefix+":"+redisSuffix)
		return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
			redisLimiter,
			policy,
			mode,
			scope,
			keyFunc,
		).Middleware()
	}
	return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
		middleware.NewLocalFixedWindowLimiter(),
		policy,
		mode,
		scope,
		keyFunc,
	).Middleware()
}

func toRateLimitPolicy(perMinute int, cfg *config.Config) middleware.RateLimitPolicy {
	window := cfg.RateLimitSustainedWindow
	if window <= 0 {
		window = time.Minute
	}
	multiplier := cfg.RateLimitBurstMultiplier
	if multiplier < 1 {
		multiplier = 1
	}
	sustainedLimit := int(math.Round(float64(perMinute) * window.Minutes()))
	if sustainedLimit <= 0 {
		sustainedLimit = 1
	}
	burstCapacity := int(math.Ceil(float64(sustainedLimit) * multiplier))
	if burstCapacity < sustainedLimit {
		burstCapacity = sustainedLimit
	}
	refill := float64(perMinute) / 60.0
	if refill <= 0 {
		refill = float64(sustainedLimit) / window.Seconds()
	}
	if refill <= 0 {
		refill = 1
	}
	return middleware.RateLimitPolicy{
		SustainedLimit:    sustainedLimit,
		SustainedWindow:   window,
		BurstCapacity:     burstCapacity,
		BurstRefillPerSec: refill,
	}
}

func provideRouterDependencies(
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	adminHandler *handler.AdminHandler,
	jwt *security.JWTManager,
	rbac service.RBACAuthorizer,
	permissionResolver service.PermissionResolver,
	globalRateLimiter router.GlobalRateLimiterFunc,
	authRateLimiter router.AuthRateLimiterFunc,
	forgotRateLimiter router.ForgotRateLimiterFunc,
	routePolicies router.RouteRateLimitPolicies,
	idempotencyFactory router.IdempotencyMiddlewareFactory,
	readiness *health.ProbeRunner,
	cfg *config.Config,
) router.Dependencies {
	return router.Dependencies{
		AuthHandler:                authHandler,
		UserHandler:                userHandler,
		AdminHandler:               adminHandler,
		JWTManager:                 jwt,
		RBACService:                rbac,
		PermissionResolver:         permissionResolver,
		CORSOrigins:                cfg.CORSAllowedOrigins,
		AuthRateLimitRPM:           cfg.AuthRateLimitPerMin,
		PasswordForgotRateLimitRPM: cfg.AuthPasswordForgotRateLimitPerMin,
		APIRateLimitRPM:            cfg.APIRateLimitPerMin,
		GlobalRateLimiter:          globalRateLimiter,
		AuthRateLimiter:            authRateLimiter,
		ForgotRateLimiter:          forgotRateLimiter,
		RouteRateLimitPolicies:     routePolicies,
		Idempotency:                idempotencyFactory,
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
	if cfg.RateLimitRedisEnabled || (cfg.IdempotencyEnabled && cfg.IdempotencyRedisEnabled) {
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
