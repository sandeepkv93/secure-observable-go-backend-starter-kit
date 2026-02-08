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

	JWTIssuer           string
	JWTAudience         string
	JWTAccessSecret     string
	JWTRefreshSecret    string
	JWTAccessTTL        time.Duration
	JWTRefreshTTL       time.Duration
	RefreshTokenPepper  string
	StateSigningSecret  string
	CookieDomain        string
	CookieSecure        bool
	CookieSameSite      string
	CORSAllowedOrigins  []string
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleRedirectURL   string
	BootstrapAdminEmail string

	AuthRateLimitPerMin int
	APIRateLimitPerMin  int

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
	cfg := &Config{
		Env:                 getEnv("APP_ENV", "development"),
		HTTPPort:            getEnv("HTTP_PORT", "8080"),
		DatabaseURL:         os.Getenv("DATABASE_URL"),
		JWTIssuer:           getEnv("JWT_ISSUER", "go-oauth-rbac-service"),
		JWTAudience:         getEnv("JWT_AUDIENCE", "go-oauth-rbac-service-api"),
		JWTAccessSecret:     os.Getenv("JWT_ACCESS_SECRET"),
		JWTRefreshSecret:    os.Getenv("JWT_REFRESH_SECRET"),
		RefreshTokenPepper:  os.Getenv("REFRESH_TOKEN_PEPPER"),
		StateSigningSecret:  os.Getenv("OAUTH_STATE_SECRET"),
		CookieDomain:        os.Getenv("COOKIE_DOMAIN"),
		CookieSecure:        getEnvBool("COOKIE_SECURE", true),
		CookieSameSite:      strings.ToLower(getEnv("COOKIE_SAMESITE", "lax")),
		CORSAllowedOrigins:  splitCSV(getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")),
		GoogleClientID:      os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		GoogleClientSecret:  os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		GoogleRedirectURL:   getEnv("GOOGLE_OAUTH_REDIRECT_URL", "http://localhost:8080/api/v1/auth/google/callback"),
		BootstrapAdminEmail: strings.TrimSpace(strings.ToLower(os.Getenv("BOOTSTRAP_ADMIN_EMAIL"))),
		AuthRateLimitPerMin: getEnvInt("AUTH_RATE_LIMIT_PER_MIN", 30),
		APIRateLimitPerMin:  getEnvInt("API_RATE_LIMIT_PER_MIN", 120),

		OTELServiceName:          getEnv("OTEL_SERVICE_NAME", "go-oauth-rbac-service"),
		OTELEnvironment:          getEnv("OTEL_ENVIRONMENT", getEnv("APP_ENV", "development")),
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

	metricsInterval, err := time.ParseDuration(getEnv("OTEL_METRICS_EXPORT_INTERVAL", "10s"))
	if err != nil {
		return nil, fmt.Errorf("parse OTEL_METRICS_EXPORT_INTERVAL: %w", err)
	}
	cfg.OTELMetricsExportInterval = metricsInterval

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
	if c.GoogleClientID == "" {
		errs = append(errs, "GOOGLE_OAUTH_CLIENT_ID is required")
	}
	if c.GoogleClientSecret == "" {
		errs = append(errs, "GOOGLE_OAUTH_CLIENT_SECRET is required")
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
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func isValidLogLevel(v string) bool {
	switch strings.ToLower(v) {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
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
