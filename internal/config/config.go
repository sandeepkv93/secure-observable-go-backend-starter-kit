package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env      string
	HTTPPort string

	DatabaseURL string

	JWTIssuer                         string
	JWTAudience                       string
	JWTAccessSecret                   string
	JWTRefreshSecret                  string
	JWTAccessTTL                      time.Duration
	JWTRefreshTTL                     time.Duration
	RefreshTokenPepper                string
	StateSigningSecret                string
	CookieDomain                      string
	CookieSecure                      bool
	CookieSameSite                    string
	CORSAllowedOrigins                []string
	GoogleClientID                    string
	GoogleClientSecret                string
	GoogleRedirectURL                 string
	AuthGoogleEnabled                 bool
	AuthLocalEnabled                  bool
	AuthLocalRequireEmailVerification bool
	AuthEmailVerifyTokenTTL           time.Duration
	AuthEmailVerifyBaseURL            string
	AuthPasswordResetTokenTTL         time.Duration
	AuthPasswordResetBaseURL          string
	AuthPasswordForgotRateLimitPerMin int
	RBACProtectedRoles                []string
	RBACProtectedPermissions          []string
	BootstrapAdminEmail               string

	AuthRateLimitPerMin          int
	APIRateLimitPerMin           int
	RateLimitLoginPerMin         int
	RateLimitRefreshPerMin       int
	RateLimitAdminWritePerMin    int
	RateLimitAdminSyncPerMin     int
	RateLimitBurstMultiplier     float64
	RateLimitSustainedWindow     time.Duration
	AuthAbuseProtectionEnabled   bool
	AuthAbuseFreeAttempts        int
	AuthAbuseBaseDelay           time.Duration
	AuthAbuseMultiplier          float64
	AuthAbuseMaxDelay            time.Duration
	AuthAbuseResetWindow         time.Duration
	AuthAbuseRedisPrefix         string
	AdminListCacheEnabled        bool
	AdminListCacheTTL            time.Duration
	AdminListCacheRedisPrefix    string
	NegativeLookupCacheEnabled   bool
	NegativeLookupCacheTTL       time.Duration
	NegativeLookupCacheRedisPref string
	RBACPermissionCacheEnabled   bool
	RBACPermissionCacheTTL       time.Duration
	RBACPermissionCacheRedisPref string
	RateLimitRedisEnabled        bool
	IdempotencyEnabled           bool
	IdempotencyRedisEnabled      bool
	IdempotencyTTL               time.Duration
	IdempotencyRedisPrefix       string
	RedisAddr                    string
	RedisPassword                string
	RedisDB                      int
	RateLimitRedisPrefix         string
	ReadinessProbeTimeout        time.Duration
	ServerStartGracePeriod       time.Duration
	ShutdownTimeout              time.Duration
	ShutdownHTTPDrainTimeout     time.Duration
	ShutdownObservabilityTimeout time.Duration

	OTELServiceName           string
	OTELEnvironment           string
	OTELExporterOTLPEndpoint  string
	OTELExporterOTLPInsecure  bool
	OTELMetricsExportInterval time.Duration
	OTELTraceSamplingRatio    float64
	OTELMetricsEnabled        bool
	OTELTracingEnabled        bool
	OTELLogsEnabled           bool
	OTELLogLevel              string
}

func Load() (*Config, error) {
	env := getEnv("APP_ENV", "development")
	googleClientID := os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET")
	googleEnabled := getEnvBool("AUTH_GOOGLE_ENABLED", true)
	if _, explicitlySet := os.LookupEnv("AUTH_GOOGLE_ENABLED"); !explicitlySet &&
		(googleClientID == "" || googleClientSecret == "") && isLocalLikeEnv(env) {
		googleEnabled = false
	}

	cfg := &Config{
		Env:                               env,
		HTTPPort:                          getEnv("HTTP_PORT", "8080"),
		DatabaseURL:                       os.Getenv("DATABASE_URL"),
		JWTIssuer:                         getEnv("JWT_ISSUER", "secure-observable-go-backend-starter-kit"),
		JWTAudience:                       getEnv("JWT_AUDIENCE", "secure-observable-go-backend-starter-kit-api"),
		JWTAccessSecret:                   os.Getenv("JWT_ACCESS_SECRET"),
		JWTRefreshSecret:                  os.Getenv("JWT_REFRESH_SECRET"),
		RefreshTokenPepper:                os.Getenv("REFRESH_TOKEN_PEPPER"),
		StateSigningSecret:                os.Getenv("OAUTH_STATE_SECRET"),
		CookieDomain:                      os.Getenv("COOKIE_DOMAIN"),
		CookieSecure:                      getEnvBool("COOKIE_SECURE", true),
		CookieSameSite:                    strings.ToLower(getEnv("COOKIE_SAMESITE", "lax")),
		CORSAllowedOrigins:                splitCSV(getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")),
		GoogleClientID:                    googleClientID,
		GoogleClientSecret:                googleClientSecret,
		GoogleRedirectURL:                 getEnv("GOOGLE_OAUTH_REDIRECT_URL", "http://localhost:8080/api/v1/auth/google/callback"),
		AuthGoogleEnabled:                 googleEnabled,
		AuthLocalEnabled:                  getEnvBool("AUTH_LOCAL_ENABLED", true),
		AuthLocalRequireEmailVerification: getEnvBool("AUTH_LOCAL_REQUIRE_EMAIL_VERIFICATION", false),
		AuthEmailVerifyBaseURL:            strings.TrimSpace(os.Getenv("AUTH_EMAIL_VERIFY_BASE_URL")),
		AuthPasswordResetBaseURL:          strings.TrimSpace(os.Getenv("AUTH_PASSWORD_RESET_BASE_URL")),
		AuthPasswordForgotRateLimitPerMin: getEnvInt("AUTH_PASSWORD_FORGOT_RATE_LIMIT_PER_MIN", 5),
		RBACProtectedRoles:                splitCSV(getEnv("RBAC_PROTECTED_ROLES", "admin,user")),
		RBACProtectedPermissions:          splitCSV(getEnv("RBAC_PROTECTED_PERMISSIONS", "users:read,users:write,roles:read,roles:write,permissions:read,permissions:write")),
		BootstrapAdminEmail:               strings.TrimSpace(strings.ToLower(os.Getenv("BOOTSTRAP_ADMIN_EMAIL"))),
		AuthRateLimitPerMin:               getEnvInt("AUTH_RATE_LIMIT_PER_MIN", 30),
		APIRateLimitPerMin:                getEnvInt("API_RATE_LIMIT_PER_MIN", 120),
		RateLimitLoginPerMin:              getEnvInt("RATE_LIMIT_LOGIN_PER_MIN", 20),
		RateLimitRefreshPerMin:            getEnvInt("RATE_LIMIT_REFRESH_PER_MIN", 30),
		RateLimitAdminWritePerMin:         getEnvInt("RATE_LIMIT_ADMIN_WRITE_PER_MIN", 30),
		RateLimitAdminSyncPerMin:          getEnvInt("RATE_LIMIT_ADMIN_SYNC_PER_MIN", 10),
		RateLimitBurstMultiplier:          getEnvFloat("RATE_LIMIT_BURST_MULTIPLIER", 1.5),
		AuthAbuseProtectionEnabled:        getEnvBool("AUTH_ABUSE_PROTECTION_ENABLED", true),
		AuthAbuseFreeAttempts:             getEnvInt("AUTH_ABUSE_FREE_ATTEMPTS", 3),
		AuthAbuseMultiplier:               getEnvFloat("AUTH_ABUSE_MULTIPLIER", 2.0),
		AdminListCacheEnabled:             getEnvBool("ADMIN_LIST_CACHE_ENABLED", true),
		AdminListCacheRedisPrefix:         getEnv("ADMIN_LIST_CACHE_REDIS_PREFIX", "admin_list_cache"),
		NegativeLookupCacheEnabled:        getEnvBool("NEGATIVE_LOOKUP_CACHE_ENABLED", true),
		NegativeLookupCacheRedisPref:      getEnv("NEGATIVE_LOOKUP_CACHE_REDIS_PREFIX", "negative_lookup_cache"),
		RBACPermissionCacheEnabled:        getEnvBool("RBAC_PERMISSION_CACHE_ENABLED", true),
		RBACPermissionCacheRedisPref:      getEnv("RBAC_PERMISSION_CACHE_REDIS_PREFIX", "rbac_perm"),
		RateLimitRedisEnabled:             getEnvBool("RATE_LIMIT_REDIS_ENABLED", true),
		IdempotencyEnabled:                getEnvBool("IDEMPOTENCY_ENABLED", true),
		IdempotencyRedisEnabled:           getEnvBool("IDEMPOTENCY_REDIS_ENABLED", true),
		RedisAddr:                         getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:                     os.Getenv("REDIS_PASSWORD"),
		RedisDB:                           getEnvInt("REDIS_DB", 0),
		RateLimitRedisPrefix:              getEnv("RATE_LIMIT_REDIS_PREFIX", "rl"),
		AuthAbuseRedisPrefix:              getEnv("AUTH_ABUSE_REDIS_PREFIX", "auth_abuse"),
		IdempotencyRedisPrefix:            getEnv("IDEMPOTENCY_REDIS_PREFIX", "idem"),

		OTELServiceName:          getEnv("OTEL_SERVICE_NAME", "secure-observable-go-backend-starter-kit"),
		OTELEnvironment:          getEnv("OTEL_ENVIRONMENT", env),
		OTELExporterOTLPEndpoint: getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
		OTELExporterOTLPInsecure: getEnvBool("OTEL_EXPORTER_OTLP_INSECURE", true),
		OTELTraceSamplingRatio:   getEnvFloat("OTEL_TRACE_SAMPLING_RATIO", 1.0),
		OTELMetricsEnabled:       getEnvBool("OTEL_METRICS_ENABLED", true),
		OTELTracingEnabled:       getEnvBool("OTEL_TRACING_ENABLED", true),
		OTELLogsEnabled:          getEnvBool("OTEL_LOGS_ENABLED", true),
		OTELLogLevel:             strings.ToLower(getEnv("OTEL_LOG_LEVEL", "info")),
	}

	accessTTL, err := time.ParseDuration(getEnv("JWT_ACCESS_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("parse JWT_ACCESS_TTL: %w", err)
	}
	cfg.JWTAccessTTL = accessTTL

	refreshTTL, err := time.ParseDuration(getEnv("JWT_REFRESH_TTL", "168h"))
	if err != nil {
		return nil, fmt.Errorf("parse JWT_REFRESH_TTL: %w", err)
	}
	cfg.JWTRefreshTTL = refreshTTL

	verifyTTL, err := time.ParseDuration(getEnv("AUTH_EMAIL_VERIFY_TOKEN_TTL", "30m"))
	if err != nil {
		return nil, fmt.Errorf("parse AUTH_EMAIL_VERIFY_TOKEN_TTL: %w", err)
	}
	cfg.AuthEmailVerifyTokenTTL = verifyTTL

	resetTTL, err := time.ParseDuration(getEnv("AUTH_PASSWORD_RESET_TOKEN_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("parse AUTH_PASSWORD_RESET_TOKEN_TTL: %w", err)
	}
	cfg.AuthPasswordResetTokenTTL = resetTTL

	metricsInterval, err := time.ParseDuration(getEnv("OTEL_METRICS_EXPORT_INTERVAL", "10s"))
	if err != nil {
		return nil, fmt.Errorf("parse OTEL_METRICS_EXPORT_INTERVAL: %w", err)
	}
	cfg.OTELMetricsExportInterval = metricsInterval

	readinessTimeout, err := time.ParseDuration(getEnv("READINESS_PROBE_TIMEOUT", "1s"))
	if err != nil {
		return nil, fmt.Errorf("parse READINESS_PROBE_TIMEOUT: %w", err)
	}
	cfg.ReadinessProbeTimeout = readinessTimeout

	idempotencyTTL, err := time.ParseDuration(getEnv("IDEMPOTENCY_TTL", "24h"))
	if err != nil {
		return nil, fmt.Errorf("parse IDEMPOTENCY_TTL: %w", err)
	}
	cfg.IdempotencyTTL = idempotencyTTL

	adminListCacheTTL, err := time.ParseDuration(getEnv("ADMIN_LIST_CACHE_TTL", "30s"))
	if err != nil {
		return nil, fmt.Errorf("parse ADMIN_LIST_CACHE_TTL: %w", err)
	}
	cfg.AdminListCacheTTL = adminListCacheTTL

	negativeLookupCacheTTL, err := time.ParseDuration(getEnv("NEGATIVE_LOOKUP_CACHE_TTL", "15s"))
	if err != nil {
		return nil, fmt.Errorf("parse NEGATIVE_LOOKUP_CACHE_TTL: %w", err)
	}
	cfg.NegativeLookupCacheTTL = negativeLookupCacheTTL

	rbacPermissionCacheTTL, err := time.ParseDuration(getEnv("RBAC_PERMISSION_CACHE_TTL", "5m"))
	if err != nil {
		return nil, fmt.Errorf("parse RBAC_PERMISSION_CACHE_TTL: %w", err)
	}
	cfg.RBACPermissionCacheTTL = rbacPermissionCacheTTL

	rateLimitSustainedWindow, err := time.ParseDuration(getEnv("RATE_LIMIT_SUSTAINED_WINDOW", "1m"))
	if err != nil {
		return nil, fmt.Errorf("parse RATE_LIMIT_SUSTAINED_WINDOW: %w", err)
	}
	cfg.RateLimitSustainedWindow = rateLimitSustainedWindow

	authAbuseBaseDelay, err := time.ParseDuration(getEnv("AUTH_ABUSE_BASE_DELAY", "2s"))
	if err != nil {
		return nil, fmt.Errorf("parse AUTH_ABUSE_BASE_DELAY: %w", err)
	}
	cfg.AuthAbuseBaseDelay = authAbuseBaseDelay

	authAbuseMaxDelay, err := time.ParseDuration(getEnv("AUTH_ABUSE_MAX_DELAY", "5m"))
	if err != nil {
		return nil, fmt.Errorf("parse AUTH_ABUSE_MAX_DELAY: %w", err)
	}
	cfg.AuthAbuseMaxDelay = authAbuseMaxDelay

	authAbuseResetWindow, err := time.ParseDuration(getEnv("AUTH_ABUSE_RESET_WINDOW", "30m"))
	if err != nil {
		return nil, fmt.Errorf("parse AUTH_ABUSE_RESET_WINDOW: %w", err)
	}
	cfg.AuthAbuseResetWindow = authAbuseResetWindow

	startGrace, err := time.ParseDuration(getEnv("SERVER_START_GRACE_PERIOD", "2s"))
	if err != nil {
		return nil, fmt.Errorf("parse SERVER_START_GRACE_PERIOD: %w", err)
	}
	cfg.ServerStartGracePeriod = startGrace

	shutdownTimeout, err := time.ParseDuration(getEnv("SHUTDOWN_TIMEOUT", "20s"))
	if err != nil {
		return nil, fmt.Errorf("parse SHUTDOWN_TIMEOUT: %w", err)
	}
	cfg.ShutdownTimeout = shutdownTimeout

	httpDrainTimeout, err := time.ParseDuration(getEnv("SHUTDOWN_HTTP_DRAIN_TIMEOUT", "10s"))
	if err != nil {
		return nil, fmt.Errorf("parse SHUTDOWN_HTTP_DRAIN_TIMEOUT: %w", err)
	}
	cfg.ShutdownHTTPDrainTimeout = httpDrainTimeout

	obsShutdownTimeout, err := time.ParseDuration(getEnv("SHUTDOWN_OBSERVABILITY_TIMEOUT", "8s"))
	if err != nil {
		return nil, fmt.Errorf("parse SHUTDOWN_OBSERVABILITY_TIMEOUT: %w", err)
	}
	cfg.ShutdownObservabilityTimeout = obsShutdownTimeout

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	var errs []string
	if c.DatabaseURL == "" {
		errs = append(errs, "DATABASE_URL is required")
	}
	if len(c.JWTAccessSecret) < 32 {
		errs = append(errs, "JWT_ACCESS_SECRET must be at least 32 chars")
	}
	if len(c.JWTRefreshSecret) < 32 {
		errs = append(errs, "JWT_REFRESH_SECRET must be at least 32 chars")
	}
	if c.JWTAccessSecret == c.JWTRefreshSecret {
		errs = append(errs, "JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must differ")
	}
	if len(c.RefreshTokenPepper) < 16 {
		errs = append(errs, "REFRESH_TOKEN_PEPPER must be at least 16 chars")
	}
	if len(c.StateSigningSecret) < 16 {
		errs = append(errs, "OAUTH_STATE_SECRET must be at least 16 chars")
	}
	if !c.AuthLocalEnabled && !c.AuthGoogleEnabled {
		errs = append(errs, "at least one auth provider must be enabled")
	}
	if c.AuthGoogleEnabled && c.GoogleClientID == "" {
		errs = append(errs, "GOOGLE_OAUTH_CLIENT_ID is required when AUTH_GOOGLE_ENABLED=true")
	}
	if c.AuthGoogleEnabled && c.GoogleClientSecret == "" {
		errs = append(errs, "GOOGLE_OAUTH_CLIENT_SECRET is required when AUTH_GOOGLE_ENABLED=true")
	}
	if c.AuthLocalRequireEmailVerification && !c.AuthLocalEnabled {
		errs = append(errs, "AUTH_LOCAL_REQUIRE_EMAIL_VERIFICATION requires AUTH_LOCAL_ENABLED=true")
	}
	if c.AuthEmailVerifyTokenTTL <= 0 || c.AuthEmailVerifyTokenTTL > (24*time.Hour) {
		errs = append(errs, "AUTH_EMAIL_VERIFY_TOKEN_TTL must be between 1s and 24h")
	}
	if c.AuthPasswordResetTokenTTL <= 0 || c.AuthPasswordResetTokenTTL > (24*time.Hour) {
		errs = append(errs, "AUTH_PASSWORD_RESET_TOKEN_TTL must be between 1s and 24h")
	}
	if c.AuthPasswordForgotRateLimitPerMin <= 0 {
		errs = append(errs, "AUTH_PASSWORD_FORGOT_RATE_LIMIT_PER_MIN must be > 0")
	}
	for _, token := range c.RBACProtectedPermissions {
		parts := strings.SplitN(strings.TrimSpace(token), ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			errs = append(errs, "RBAC_PROTECTED_PERMISSIONS entries must use resource:action format")
			break
		}
	}
	if c.JWTAccessTTL <= 0 || c.JWTAccessTTL > time.Hour {
		errs = append(errs, "JWT_ACCESS_TTL must be between 1s and 1h")
	}
	if c.JWTRefreshTTL <= 0 || c.JWTRefreshTTL > (30*24*time.Hour) {
		errs = append(errs, "JWT_REFRESH_TTL must be between 1s and 30d")
	}
	if c.AuthRateLimitPerMin <= 0 {
		errs = append(errs, "AUTH_RATE_LIMIT_PER_MIN must be > 0")
	}
	if c.APIRateLimitPerMin <= 0 {
		errs = append(errs, "API_RATE_LIMIT_PER_MIN must be > 0")
	}
	if c.RateLimitLoginPerMin <= 0 {
		errs = append(errs, "RATE_LIMIT_LOGIN_PER_MIN must be > 0")
	}
	if c.RateLimitRefreshPerMin <= 0 {
		errs = append(errs, "RATE_LIMIT_REFRESH_PER_MIN must be > 0")
	}
	if c.RateLimitAdminWritePerMin <= 0 {
		errs = append(errs, "RATE_LIMIT_ADMIN_WRITE_PER_MIN must be > 0")
	}
	if c.RateLimitAdminSyncPerMin <= 0 {
		errs = append(errs, "RATE_LIMIT_ADMIN_SYNC_PER_MIN must be > 0")
	}
	if c.RateLimitBurstMultiplier < 1 || c.RateLimitBurstMultiplier > 10 {
		errs = append(errs, "RATE_LIMIT_BURST_MULTIPLIER must be between 1 and 10")
	}
	if c.RateLimitSustainedWindow < time.Second || c.RateLimitSustainedWindow > (15*time.Minute) {
		errs = append(errs, "RATE_LIMIT_SUSTAINED_WINDOW must be between 1s and 15m")
	}
	if c.AuthAbuseFreeAttempts < 0 || c.AuthAbuseFreeAttempts > 20 {
		errs = append(errs, "AUTH_ABUSE_FREE_ATTEMPTS must be between 0 and 20")
	}
	if c.AuthAbuseBaseDelay < time.Second || c.AuthAbuseBaseDelay > time.Minute {
		errs = append(errs, "AUTH_ABUSE_BASE_DELAY must be between 1s and 1m")
	}
	if c.AuthAbuseMultiplier < 1 || c.AuthAbuseMultiplier > 10 {
		errs = append(errs, "AUTH_ABUSE_MULTIPLIER must be between 1 and 10")
	}
	if c.AuthAbuseMaxDelay < c.AuthAbuseBaseDelay || c.AuthAbuseMaxDelay > time.Hour {
		errs = append(errs, "AUTH_ABUSE_MAX_DELAY must be >= AUTH_ABUSE_BASE_DELAY and <= 1h")
	}
	if c.AuthAbuseResetWindow < time.Minute || c.AuthAbuseResetWindow > (24*time.Hour) {
		errs = append(errs, "AUTH_ABUSE_RESET_WINDOW must be between 1m and 24h")
	}
	if c.AdminListCacheEnabled && (c.AdminListCacheTTL <= 0 || c.AdminListCacheTTL > (10*time.Minute)) {
		errs = append(errs, "ADMIN_LIST_CACHE_TTL must be between 1s and 10m when admin list cache is enabled")
	}
	if c.NegativeLookupCacheEnabled && (c.NegativeLookupCacheTTL <= 0 || c.NegativeLookupCacheTTL > time.Minute) {
		errs = append(errs, "NEGATIVE_LOOKUP_CACHE_TTL must be between 1s and 1m when negative lookup cache is enabled")
	}
	if c.RBACPermissionCacheEnabled && (c.RBACPermissionCacheTTL <= 0 || c.RBACPermissionCacheTTL > (30*time.Minute)) {
		errs = append(errs, "RBAC_PERMISSION_CACHE_TTL must be between 1s and 30m when rbac permission cache is enabled")
	}
	if c.IdempotencyTTL <= 0 || c.IdempotencyTTL > (7*24*time.Hour) {
		errs = append(errs, "IDEMPOTENCY_TTL must be between 1s and 168h")
	}
	if (c.RateLimitRedisEnabled || (c.IdempotencyEnabled && c.IdempotencyRedisEnabled) || c.AdminListCacheEnabled || c.NegativeLookupCacheEnabled || c.RBACPermissionCacheEnabled) && strings.TrimSpace(c.RedisAddr) == "" {
		errs = append(errs, "REDIS_ADDR is required when Redis-backed features are enabled")
	}
	if c.ReadinessProbeTimeout <= 0 {
		errs = append(errs, "READINESS_PROBE_TIMEOUT must be > 0")
	}
	if c.ShutdownTimeout <= 0 {
		errs = append(errs, "SHUTDOWN_TIMEOUT must be > 0")
	}
	if c.ShutdownHTTPDrainTimeout <= 0 {
		errs = append(errs, "SHUTDOWN_HTTP_DRAIN_TIMEOUT must be > 0")
	}
	if c.ShutdownObservabilityTimeout <= 0 {
		errs = append(errs, "SHUTDOWN_OBSERVABILITY_TIMEOUT must be > 0")
	}
	if c.ShutdownHTTPDrainTimeout > c.ShutdownTimeout {
		errs = append(errs, "SHUTDOWN_HTTP_DRAIN_TIMEOUT must be <= SHUTDOWN_TIMEOUT")
	}
	if c.ShutdownObservabilityTimeout > c.ShutdownTimeout {
		errs = append(errs, "SHUTDOWN_OBSERVABILITY_TIMEOUT must be <= SHUTDOWN_TIMEOUT")
	}
	if (c.OTELMetricsEnabled || c.OTELTracingEnabled || c.OTELLogsEnabled) && c.OTELExporterOTLPEndpoint == "" {
		errs = append(errs, "OTEL_EXPORTER_OTLP_ENDPOINT is required when OTel is enabled")
	}
	if c.OTELTraceSamplingRatio < 0 || c.OTELTraceSamplingRatio > 1 {
		errs = append(errs, "OTEL_TRACE_SAMPLING_RATIO must be between 0 and 1")
	}
	if c.OTELMetricsExportInterval <= 0 {
		errs = append(errs, "OTEL_METRICS_EXPORT_INTERVAL must be > 0")
	}
	if !isValidLogLevel(c.OTELLogLevel) {
		errs = append(errs, "OTEL_LOG_LEVEL must be one of debug, info, warn, error")
	}
	if c.isProdLike() {
		if !c.CookieSecure {
			errs = append(errs, "COOKIE_SECURE must be true in production/staging")
		}
		switch c.CookieSameSite {
		case "lax", "strict":
		default:
			errs = append(errs, "COOKIE_SAMESITE must be lax or strict in production/staging")
		}
		if !c.RateLimitRedisEnabled {
			errs = append(errs, "RATE_LIMIT_REDIS_ENABLED must be true in production/staging")
		}
		if isLoopbackAddr(c.RedisAddr) {
			errs = append(errs, "REDIS_ADDR must not be loopback in production/staging")
		}
		if c.OTELTraceSamplingRatio > 0.2 {
			errs = append(errs, "OTEL_TRACE_SAMPLING_RATIO must be <= 0.2 in production/staging")
		}
		if looksPlaceholder(c.JWTAccessSecret) || looksPlaceholder(c.JWTRefreshSecret) ||
			looksPlaceholder(c.RefreshTokenPepper) || looksPlaceholder(c.StateSigningSecret) {
			errs = append(errs, "secrets must not use placeholder values in production/staging")
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func isLocalLikeEnv(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "development", "dev", "local", "test":
		return true
	default:
		return false
	}
}

func isValidLogLevel(v string) bool {
	switch strings.ToLower(v) {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}

func (c *Config) isProdLike() bool {
	switch strings.ToLower(strings.TrimSpace(c.Env)) {
	case "production", "prod", "staging", "stage", "preprod":
		return true
	default:
		return false
	}
}

func isLoopbackAddr(addr string) bool {
	addr = strings.TrimSpace(strings.ToLower(addr))
	return strings.HasPrefix(addr, "localhost:") ||
		strings.HasPrefix(addr, "127.0.0.1:") ||
		strings.HasPrefix(addr, "0.0.0.0:")
}

func looksPlaceholder(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return strings.Contains(v, "replace-with") || strings.Contains(v, "changeme") || strings.Contains(v, "example")
}

func getEnv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getEnvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getEnvFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trim := strings.TrimSpace(p)
		if trim != "" {
			out = append(out, trim)
		}
	}
	return out
}
