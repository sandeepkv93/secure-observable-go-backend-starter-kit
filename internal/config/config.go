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
	BootstrapAdminEmail               string

	AuthRateLimitPerMin          int
	APIRateLimitPerMin           int
	RateLimitRedisEnabled        bool
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
		BootstrapAdminEmail:               strings.TrimSpace(strings.ToLower(os.Getenv("BOOTSTRAP_ADMIN_EMAIL"))),
		AuthRateLimitPerMin:               getEnvInt("AUTH_RATE_LIMIT_PER_MIN", 30),
		APIRateLimitPerMin:                getEnvInt("API_RATE_LIMIT_PER_MIN", 120),
		RateLimitRedisEnabled:             getEnvBool("RATE_LIMIT_REDIS_ENABLED", true),
		RedisAddr:                         getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:                     os.Getenv("REDIS_PASSWORD"),
		RedisDB:                           getEnvInt("REDIS_DB", 0),
		RateLimitRedisPrefix:              getEnv("RATE_LIMIT_REDIS_PREFIX", "rl"),

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
	if c.RateLimitRedisEnabled && strings.TrimSpace(c.RedisAddr) == "" {
		errs = append(errs, "REDIS_ADDR is required when RATE_LIMIT_REDIS_ENABLED=true")
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
