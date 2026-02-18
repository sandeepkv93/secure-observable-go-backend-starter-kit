package di

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/wire"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/app"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/database"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/health"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/handler"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/router"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
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
	repository.NewFeatureFlagRepository,
	repository.NewProductRepository,
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
	provideStorageService,
	service.NewGoogleOAuthProvider,
	service.NewDevEmailVerificationNotifier,
	wire.Bind(new(service.EmailVerificationNotifier), new(*service.DevEmailVerificationNotifier)),
	wire.Bind(new(service.PasswordResetNotifier), new(*service.DevEmailVerificationNotifier)),
	wire.Bind(new(service.OAuthProvider), new(*service.GoogleOAuthProvider)),
	service.NewOAuthService,
	service.NewAuthService,
	provideFeatureFlagEvaluationCacheStore,
	service.NewFeatureFlagService,
	service.NewProductService,
	wire.Bind(new(service.UserServiceInterface), new(*service.UserService)),
	wire.Bind(new(service.SessionServiceInterface), new(*service.SessionService)),
	wire.Bind(new(service.AuthServiceInterface), new(*service.AuthService)),
	wire.Bind(new(service.RBACAuthorizer), new(*service.RBACService)),
	wire.Bind(new(service.FeatureFlagService), new(*service.DefaultFeatureFlagService)),
	wire.Bind(new(service.ProductService), new(*service.ProductServiceImpl)),
)

var HTTPSet = wire.NewSet(
	provideRequestBypassEvaluator,
	provideAuthHandler,
	provideAuthAbuseGuard,
	handler.NewUserHandler,
	provideRBACPermissionCacheStore,
	providePermissionResolver,
	provideAdminListCacheStore,
	provideNegativeLookupCacheStore,
	handler.NewAdminHandler,
	handler.NewFeatureFlagHandler,
	handler.NewProductHandler,
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
		!cfg.RBACPermissionCacheEnabled &&
		!cfg.FeatureFlagEvalCacheRedis {
		return nil
	}
	options := &redis.Options{
		Addr:            cfg.RedisAddr,
		Username:        cfg.RedisUsername,
		Password:        cfg.RedisPassword,
		DB:              cfg.RedisDB,
		DialTimeout:     cfg.RedisDialTimeout,
		ReadTimeout:     cfg.RedisReadTimeout,
		WriteTimeout:    cfg.RedisWriteTimeout,
		MaxRetries:      cfg.RedisMaxRetries,
		MinRetryBackoff: cfg.RedisMinRetryBackoff,
		MaxRetryBackoff: cfg.RedisMaxRetryBackoff,
		PoolSize:        cfg.RedisPoolSize,
		MinIdleConns:    cfg.RedisMinIdleConns,
		PoolTimeout:     cfg.RedisPoolTimeout,
	}
	if cfg.RedisTLSEnabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: strings.TrimSpace(cfg.RedisTLSServerName),
			// #nosec G402 -- Explicit operator-controlled toggle; validation blocks it for non-local envs.
			InsecureSkipVerify: cfg.RedisTLSInsecureSkipVerify,
		}
		if certPath := strings.TrimSpace(cfg.RedisTLSCACertFile); certPath != "" {
			// #nosec G304 -- Path is operator-provided configuration and validated at startup.
			pemBytes, err := os.ReadFile(certPath)
			if err != nil {
				slog.Warn("redis tls ca cert file unreadable, falling back to system roots", "path", certPath, "error", err.Error())
			} else {
				pool, err := x509.SystemCertPool()
				if err != nil || pool == nil {
					pool = x509.NewCertPool()
				}
				if !pool.AppendCertsFromPEM(pemBytes) {
					slog.Warn("redis tls ca cert file contains no valid certs, falling back to system roots", "path", certPath)
				} else {
					tlsConfig.RootCAs = pool
				}
			}
		}
		options.TLSConfig = tlsConfig
	}
	client := redis.NewClient(options)
	observability.InstrumentRedisClient(client, slog.Default())
	return client
}

func composeRedisPrefix(namespace, prefix string) string {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = "v1"
	}
	p := strings.TrimSpace(prefix)
	if p == "" {
		return ns
	}
	return ns + ":" + p
}

func provideRBACPermissionCacheStore(cfg *config.Config, redisClient redis.UniversalClient) service.RBACPermissionCacheStore {
	if !cfg.RBACPermissionCacheEnabled {
		return service.NewNoopRBACPermissionCacheStore()
	}
	if redisClient == nil {
		return service.NewNoopRBACPermissionCacheStore()
	}
	return service.NewRedisRBACPermissionCacheStore(redisClient, composeRedisPrefix(cfg.RedisKeyNamespace, cfg.RBACPermissionCacheRedisPref))
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
	return service.NewRedisAdminListCacheStore(redisClient, composeRedisPrefix(cfg.RedisKeyNamespace, cfg.AdminListCacheRedisPrefix))
}

func provideNegativeLookupCacheStore(cfg *config.Config, redisClient redis.UniversalClient) service.NegativeLookupCacheStore {
	if !cfg.NegativeLookupCacheEnabled {
		return service.NewNoopNegativeLookupCacheStore()
	}
	if redisClient == nil {
		return service.NewNoopNegativeLookupCacheStore()
	}
	return service.NewRedisNegativeLookupCacheStore(redisClient, composeRedisPrefix(cfg.RedisKeyNamespace, cfg.NegativeLookupCacheRedisPref))
}

func provideFeatureFlagEvaluationCacheStore(cfg *config.Config, redisClient redis.UniversalClient) service.FeatureFlagEvaluationCacheStore {
	if !cfg.FeatureFlagEvalCacheRedis || redisClient == nil {
		return service.NewInMemoryFeatureFlagEvaluationCacheStore()
	}
	return service.NewRedisFeatureFlagEvaluationCacheStore(redisClient, composeRedisPrefix(cfg.RedisKeyNamespace, "feature_flag_eval_cache"))
}

func provideIdempotencyStore(cfg *config.Config, db *gorm.DB, redisClient redis.UniversalClient) service.IdempotencyStore {
	if !cfg.IdempotencyEnabled {
		return nil
	}
	if cfg.IdempotencyRedisEnabled && redisClient != nil {
		return service.NewRedisIdempotencyStore(redisClient, composeRedisPrefix(cfg.RedisKeyNamespace, cfg.IdempotencyRedisPrefix))
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

func provideStorageService(cfg *config.Config) (service.StorageService, error) {
	return service.NewMinIOStorageService(
		cfg.MinIOEndpoint,
		cfg.MinIOAccessKey,
		cfg.MinIOSecretKey,
		cfg.MinIOBucketName,
		cfg.MinIOUseSSL,
	)
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
		return service.NewRedisAuthAbuseGuard(redisClient, composeRedisPrefix(cfg.RedisKeyNamespace, cfg.AuthAbuseRedisPrefix), policy)
	}
	return service.NewInMemoryAuthAbuseGuard(policy)
}

func provideAuthHandler(
	authSvc service.AuthServiceInterface,
	abuseGuard service.AuthAbuseGuard,
	cookieMgr *security.CookieManager,
	bypassEvaluator middleware.BypassEvaluator,
	cfg *config.Config,
) *handler.AuthHandler {
	return handler.NewAuthHandler(authSvc, abuseGuard, cookieMgr, bypassEvaluator, cfg.StateSigningSecret, cfg.JWTRefreshTTL)
}

func provideRequestBypassEvaluator(cfg *config.Config, jwt *security.JWTManager) middleware.BypassEvaluator {
	return middleware.NewRequestBypassEvaluator(middleware.RequestBypassConfig{
		EnableInternalProbeBypass: cfg.BypassInternalProbes,
		EnableTrustedActorBypass:  cfg.BypassTrustedActors,
		TrustedActorCIDRs:         cfg.BypassTrustedActorCIDRs,
		TrustedActorSubjects:      cfg.BypassTrustedActorSubjects,
	}, jwt)
}

func provideGlobalRateLimiter(
	cfg *config.Config,
	redisClient redis.UniversalClient,
	jwt *security.JWTManager,
	bypassEvaluator middleware.BypassEvaluator,
) router.GlobalRateLimiterFunc {
	keyFunc := middleware.SubjectOrIPKeyFunc(jwt)
	policy := toRateLimitPolicy(cfg.APIRateLimitPerMin, cfg)
	rateLimitPrefix := composeRedisPrefix(cfg.RedisKeyNamespace, cfg.RateLimitRedisPrefix)
	outageMode := toRateLimitFailureMode(cfg.RateLimitOutagePolicyAPI, middleware.FailOpen)
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, rateLimitPrefix+":api")
		return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
			redisLimiter,
			policy,
			outageMode,
			"api",
			keyFunc,
		).WithBypassEvaluator(bypassEvaluator).Middleware()
	}
	return middleware.NewRateLimiterWithPolicy(policy, keyFunc).WithBypassEvaluator(bypassEvaluator).Middleware()
}

func provideAuthRateLimiter(
	cfg *config.Config,
	redisClient redis.UniversalClient,
	bypassEvaluator middleware.BypassEvaluator,
) router.AuthRateLimiterFunc {
	policy := toRateLimitPolicy(cfg.AuthRateLimitPerMin, cfg)
	rateLimitPrefix := composeRedisPrefix(cfg.RedisKeyNamespace, cfg.RateLimitRedisPrefix)
	outageMode := toRateLimitFailureMode(cfg.RateLimitOutagePolicyAuth, middleware.FailClosed)
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, rateLimitPrefix+":auth")
		return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
			redisLimiter,
			policy,
			outageMode,
			"auth",
			nil,
		).WithBypassEvaluator(bypassEvaluator).Middleware()
	}
	return middleware.NewRateLimiterWithPolicy(policy, nil).WithBypassEvaluator(bypassEvaluator).Middleware()
}

func provideForgotRateLimiter(
	cfg *config.Config,
	redisClient redis.UniversalClient,
	bypassEvaluator middleware.BypassEvaluator,
) router.ForgotRateLimiterFunc {
	policy := toRateLimitPolicy(cfg.AuthPasswordForgotRateLimitPerMin, cfg)
	rateLimitPrefix := composeRedisPrefix(cfg.RedisKeyNamespace, cfg.RateLimitRedisPrefix)
	outageMode := toRateLimitFailureMode(cfg.RateLimitOutagePolicyForgot, middleware.FailClosed)
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, rateLimitPrefix+":auth:forgot")
		return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
			redisLimiter,
			policy,
			outageMode,
			"auth_password_forgot",
			nil,
		).WithBypassEvaluator(bypassEvaluator).Middleware()
	}
	return middleware.NewRateLimiterWithPolicy(policy, nil).WithBypassEvaluator(bypassEvaluator).Middleware()
}

func provideRouteRateLimitPolicies(
	cfg *config.Config,
	redisClient redis.UniversalClient,
	jwt *security.JWTManager,
	bypassEvaluator middleware.BypassEvaluator,
) router.RouteRateLimitPolicies {
	policies := make(router.RouteRateLimitPolicies, 4)
	policies[router.RoutePolicyLogin] = buildRoutePolicyLimiter(
		cfg,
		redisClient,
		"route:login",
		cfg.RateLimitLoginPerMin,
		toRateLimitFailureMode(cfg.RateLimitOutagePolicyLogin, middleware.FailClosed),
		"route_login",
		nil,
		bypassEvaluator,
	)
	policies[router.RoutePolicyRefresh] = buildRoutePolicyLimiter(
		cfg,
		redisClient,
		"route:refresh",
		cfg.RateLimitRefreshPerMin,
		toRateLimitFailureMode(cfg.RateLimitOutagePolicyRefresh, middleware.FailClosed),
		"route_refresh",
		middleware.SubjectOrIPKeyFunc(jwt),
		bypassEvaluator,
	)
	subjectKey := middleware.SubjectOrIPKeyFunc(jwt)
	policies[router.RoutePolicyAdminWrite] = buildRoutePolicyLimiter(
		cfg,
		redisClient,
		"route:admin:write",
		cfg.RateLimitAdminWritePerMin,
		toRateLimitFailureMode(cfg.RateLimitOutagePolicyAdminW, middleware.FailClosed),
		"route_admin_write",
		subjectKey,
		bypassEvaluator,
	)
	policies[router.RoutePolicyAdminSync] = buildRoutePolicyLimiter(
		cfg,
		redisClient,
		"route:admin:sync",
		cfg.RateLimitAdminSyncPerMin,
		toRateLimitFailureMode(cfg.RateLimitOutagePolicyAdminS, middleware.FailClosed),
		"route_admin_sync",
		subjectKey,
		bypassEvaluator,
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
	bypassEvaluator middleware.BypassEvaluator,
) func(http.Handler) http.Handler {
	policy := toRateLimitPolicy(limit, cfg)
	rateLimitPrefix := composeRedisPrefix(cfg.RedisKeyNamespace, cfg.RateLimitRedisPrefix)
	if cfg.RateLimitRedisEnabled && redisClient != nil {
		redisLimiter := middleware.NewRedisFixedWindowLimiter(redisClient, rateLimitPrefix+":"+redisSuffix)
		return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
			redisLimiter,
			policy,
			mode,
			scope,
			keyFunc,
		).WithBypassEvaluator(bypassEvaluator).Middleware()
	}
	return middleware.NewDistributedRateLimiterWithKeyAndPolicy(
		middleware.NewLocalFixedWindowLimiter(),
		policy,
		mode,
		scope,
		keyFunc,
	).WithBypassEvaluator(bypassEvaluator).Middleware()
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

func toRateLimitFailureMode(raw string, fallback middleware.FailureMode) middleware.FailureMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(middleware.FailOpen):
		return middleware.FailOpen
	case string(middleware.FailClosed):
		return middleware.FailClosed
	default:
		return fallback
	}
}

func provideRouterDependencies(
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	adminHandler *handler.AdminHandler,
	featureFlagHandler *handler.FeatureFlagHandler,
	productHandler *handler.ProductHandler,
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
		FeatureFlagHandler:         featureFlagHandler,
		ProductHandler:             productHandler,
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
	idempotencyStore service.IdempotencyStore,
) *app.App {
	stopBackgroundTasks := startDBIdempotencyCleanup(cfg, logger, idempotencyStore)
	return app.New(cfg, logger, server, runtime, db, redisClient, readiness, stopBackgroundTasks)
}

func startDBIdempotencyCleanup(
	cfg *config.Config,
	logger *slog.Logger,
	store service.IdempotencyStore,
) func() {
	if !cfg.IdempotencyEnabled || cfg.IdempotencyRedisEnabled || !cfg.IdempotencyDBCleanupEnabled {
		return nil
	}
	dbStore, ok := store.(*service.DBIdempotencyStore)
	if !ok || dbStore == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	go dbStore.RunCleanupLoop(ctx, cfg.IdempotencyDBCleanupInterval, cfg.IdempotencyDBCleanupBatch, logger)
	return cancel
}
