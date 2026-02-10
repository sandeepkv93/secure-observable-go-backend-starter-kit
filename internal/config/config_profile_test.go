package config

import (
	"testing"
	"time"
)

func TestValidateProdProfileStrictRules(t *testing.T) {
	cfg := &Config{
		Env:                               "production",
		DatabaseURL:                       "postgres://x",
		JWTAccessSecret:                   "abcdefghijklmnopqrstuvwxyz123456",
		JWTRefreshSecret:                  "abcdefghijklmnopqrstuvwxyz654321",
		RefreshTokenPepper:                "pepper-1234567890",
		StateSigningSecret:                "state-secret-12345",
		AuthLocalEnabled:                  true,
		AuthGoogleEnabled:                 false,
		JWTAccessTTL:                      15 * time.Minute,
		JWTRefreshTTL:                     24 * time.Hour,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		AuthPasswordForgotRateLimitPerMin: 5,
		RBACProtectedRoles:                []string{"admin", "user"},
		RBACProtectedPermissions:          []string{"roles:write", "permissions:write"},
		AuthRateLimitPerMin:               30,
		APIRateLimitPerMin:                120,
		RateLimitLoginPerMin:              20,
		RateLimitRefreshPerMin:            30,
		RateLimitAdminWritePerMin:         30,
		RateLimitAdminSyncPerMin:          10,
		RateLimitBurstMultiplier:          1.5,
		RateLimitSustainedWindow:          time.Minute,
		AuthAbuseFreeAttempts:             3,
		AuthAbuseBaseDelay:                2 * time.Second,
		AuthAbuseMultiplier:               2.0,
		AuthAbuseMaxDelay:                 5 * time.Minute,
		AuthAbuseResetWindow:              30 * time.Minute,
		RateLimitRedisEnabled:             true,
		IdempotencyEnabled:                true,
		IdempotencyRedisEnabled:           true,
		IdempotencyTTL:                    24 * time.Hour,
		RedisAddr:                         "localhost:6379",
		RedisDialTimeout:                  5 * time.Second,
		RedisReadTimeout:                  3 * time.Second,
		RedisWriteTimeout:                 3 * time.Second,
		RedisMaxRetries:                   3,
		RedisMinRetryBackoff:              8 * time.Millisecond,
		RedisMaxRetryBackoff:              512 * time.Millisecond,
		RedisPoolSize:                     10,
		RedisMinIdleConns:                 2,
		RedisPoolTimeout:                  4 * time.Second,
		CookieSecure:                      false,
		CookieSameSite:                    "none",
		OTELTraceSamplingRatio:            1.0,
		OTELMetricsExportInterval:         10 * time.Second,
		OTELLogLevel:                      "info",
		ReadinessProbeTimeout:             1 * time.Second,
		ShutdownTimeout:                   20 * time.Second,
		ShutdownHTTPDrainTimeout:          10 * time.Second,
		ShutdownObservabilityTimeout:      8 * time.Second,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected strict prod validation errors")
	}
}

func TestValidateDevelopmentProfileAllowsRelaxedSettings(t *testing.T) {
	cfg := &Config{
		Env:                               "development",
		DatabaseURL:                       "postgres://x",
		JWTAccessSecret:                   "abcdefghijklmnopqrstuvwxyz123456",
		JWTRefreshSecret:                  "abcdefghijklmnopqrstuvwxyz654321",
		RefreshTokenPepper:                "pepper-1234567890",
		StateSigningSecret:                "state-secret-12345",
		AuthLocalEnabled:                  true,
		AuthGoogleEnabled:                 false,
		JWTAccessTTL:                      15 * time.Minute,
		JWTRefreshTTL:                     24 * time.Hour,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		AuthPasswordForgotRateLimitPerMin: 5,
		RBACProtectedRoles:                []string{"admin", "user"},
		RBACProtectedPermissions:          []string{"roles:write", "permissions:write"},
		AuthRateLimitPerMin:               30,
		APIRateLimitPerMin:                120,
		RateLimitLoginPerMin:              20,
		RateLimitRefreshPerMin:            30,
		RateLimitAdminWritePerMin:         30,
		RateLimitAdminSyncPerMin:          10,
		RateLimitBurstMultiplier:          1.5,
		RateLimitSustainedWindow:          time.Minute,
		AuthAbuseFreeAttempts:             3,
		AuthAbuseBaseDelay:                2 * time.Second,
		AuthAbuseMultiplier:               2.0,
		AuthAbuseMaxDelay:                 5 * time.Minute,
		AuthAbuseResetWindow:              30 * time.Minute,
		RateLimitRedisEnabled:             true,
		IdempotencyEnabled:                true,
		IdempotencyRedisEnabled:           true,
		IdempotencyTTL:                    24 * time.Hour,
		RedisAddr:                         "localhost:6379",
		RedisDialTimeout:                  5 * time.Second,
		RedisReadTimeout:                  3 * time.Second,
		RedisWriteTimeout:                 3 * time.Second,
		RedisMaxRetries:                   3,
		RedisMinRetryBackoff:              8 * time.Millisecond,
		RedisMaxRetryBackoff:              512 * time.Millisecond,
		RedisPoolSize:                     10,
		RedisMinIdleConns:                 2,
		RedisPoolTimeout:                  4 * time.Second,
		CookieSecure:                      false,
		CookieSameSite:                    "none",
		OTELTraceSamplingRatio:            1.0,
		OTELMetricsExportInterval:         10 * time.Second,
		OTELLogLevel:                      "info",
		ReadinessProbeTimeout:             1 * time.Second,
		ShutdownTimeout:                   20 * time.Second,
		ShutdownHTTPDrainTimeout:          10 * time.Second,
		ShutdownObservabilityTimeout:      8 * time.Second,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected relaxed dev validation to pass: %v", err)
	}
}

func TestValidateTrustedActorBypassRequiresAllowlist(t *testing.T) {
	cfg := &Config{
		Env:                               "development",
		DatabaseURL:                       "postgres://x",
		JWTAccessSecret:                   "abcdefghijklmnopqrstuvwxyz123456",
		JWTRefreshSecret:                  "abcdefghijklmnopqrstuvwxyz654321",
		RefreshTokenPepper:                "pepper-1234567890",
		StateSigningSecret:                "state-secret-12345",
		AuthLocalEnabled:                  true,
		AuthGoogleEnabled:                 false,
		JWTAccessTTL:                      15 * time.Minute,
		JWTRefreshTTL:                     24 * time.Hour,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		AuthPasswordForgotRateLimitPerMin: 5,
		RBACProtectedRoles:                []string{"admin", "user"},
		RBACProtectedPermissions:          []string{"roles:write", "permissions:write"},
		AuthRateLimitPerMin:               30,
		APIRateLimitPerMin:                120,
		RateLimitLoginPerMin:              20,
		RateLimitRefreshPerMin:            30,
		RateLimitAdminWritePerMin:         30,
		RateLimitAdminSyncPerMin:          10,
		RateLimitBurstMultiplier:          1.5,
		RateLimitSustainedWindow:          time.Minute,
		AuthAbuseFreeAttempts:             3,
		AuthAbuseBaseDelay:                2 * time.Second,
		AuthAbuseMultiplier:               2.0,
		AuthAbuseMaxDelay:                 5 * time.Minute,
		AuthAbuseResetWindow:              30 * time.Minute,
		BypassTrustedActors:               true,
		RateLimitRedisEnabled:             true,
		IdempotencyEnabled:                true,
		IdempotencyRedisEnabled:           true,
		IdempotencyTTL:                    24 * time.Hour,
		RedisAddr:                         "localhost:6379",
		RedisDialTimeout:                  5 * time.Second,
		RedisReadTimeout:                  3 * time.Second,
		RedisWriteTimeout:                 3 * time.Second,
		RedisMaxRetries:                   3,
		RedisMinRetryBackoff:              8 * time.Millisecond,
		RedisMaxRetryBackoff:              512 * time.Millisecond,
		RedisPoolSize:                     10,
		RedisMinIdleConns:                 2,
		RedisPoolTimeout:                  4 * time.Second,
		CookieSecure:                      false,
		CookieSameSite:                    "none",
		OTELTraceSamplingRatio:            1.0,
		OTELMetricsExportInterval:         10 * time.Second,
		OTELLogLevel:                      "info",
		ReadinessProbeTimeout:             1 * time.Second,
		ShutdownTimeout:                   20 * time.Second,
		ShutdownHTTPDrainTimeout:          10 * time.Second,
		ShutdownObservabilityTimeout:      8 * time.Second,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when trusted bypass is enabled without allowlist")
	}
}

func TestValidateTrustedActorBypassAcceptsCIDR(t *testing.T) {
	cfg := &Config{
		Env:                               "development",
		DatabaseURL:                       "postgres://x",
		JWTAccessSecret:                   "abcdefghijklmnopqrstuvwxyz123456",
		JWTRefreshSecret:                  "abcdefghijklmnopqrstuvwxyz654321",
		RefreshTokenPepper:                "pepper-1234567890",
		StateSigningSecret:                "state-secret-12345",
		AuthLocalEnabled:                  true,
		AuthGoogleEnabled:                 false,
		JWTAccessTTL:                      15 * time.Minute,
		JWTRefreshTTL:                     24 * time.Hour,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		AuthPasswordForgotRateLimitPerMin: 5,
		RBACProtectedRoles:                []string{"admin", "user"},
		RBACProtectedPermissions:          []string{"roles:write", "permissions:write"},
		AuthRateLimitPerMin:               30,
		APIRateLimitPerMin:                120,
		RateLimitLoginPerMin:              20,
		RateLimitRefreshPerMin:            30,
		RateLimitAdminWritePerMin:         30,
		RateLimitAdminSyncPerMin:          10,
		RateLimitBurstMultiplier:          1.5,
		RateLimitSustainedWindow:          time.Minute,
		AuthAbuseFreeAttempts:             3,
		AuthAbuseBaseDelay:                2 * time.Second,
		AuthAbuseMultiplier:               2.0,
		AuthAbuseMaxDelay:                 5 * time.Minute,
		AuthAbuseResetWindow:              30 * time.Minute,
		BypassTrustedActors:               true,
		BypassTrustedActorCIDRs:           []string{"10.0.0.0/8"},
		RateLimitRedisEnabled:             true,
		IdempotencyEnabled:                true,
		IdempotencyRedisEnabled:           true,
		IdempotencyTTL:                    24 * time.Hour,
		RedisAddr:                         "localhost:6379",
		RedisDialTimeout:                  5 * time.Second,
		RedisReadTimeout:                  3 * time.Second,
		RedisWriteTimeout:                 3 * time.Second,
		RedisMaxRetries:                   3,
		RedisMinRetryBackoff:              8 * time.Millisecond,
		RedisMaxRetryBackoff:              512 * time.Millisecond,
		RedisPoolSize:                     10,
		RedisMinIdleConns:                 2,
		RedisPoolTimeout:                  4 * time.Second,
		CookieSecure:                      false,
		CookieSameSite:                    "none",
		OTELTraceSamplingRatio:            1.0,
		OTELMetricsExportInterval:         10 * time.Second,
		OTELLogLevel:                      "info",
		ReadinessProbeTimeout:             1 * time.Second,
		ShutdownTimeout:                   20 * time.Second,
		ShutdownHTTPDrainTimeout:          10 * time.Second,
		ShutdownObservabilityTimeout:      8 * time.Second,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected trusted bypass with cidr to pass validation: %v", err)
	}
}

func TestValidateRedisPoolSettings(t *testing.T) {
	cfg := &Config{
		Env:                               "development",
		DatabaseURL:                       "postgres://x",
		JWTAccessSecret:                   "abcdefghijklmnopqrstuvwxyz123456",
		JWTRefreshSecret:                  "abcdefghijklmnopqrstuvwxyz654321",
		RefreshTokenPepper:                "pepper-1234567890",
		StateSigningSecret:                "state-secret-12345",
		AuthLocalEnabled:                  true,
		AuthGoogleEnabled:                 false,
		JWTAccessTTL:                      15 * time.Minute,
		JWTRefreshTTL:                     24 * time.Hour,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		AuthPasswordForgotRateLimitPerMin: 5,
		RBACProtectedRoles:                []string{"admin", "user"},
		RBACProtectedPermissions:          []string{"roles:write", "permissions:write"},
		AuthRateLimitPerMin:               30,
		APIRateLimitPerMin:                120,
		RateLimitLoginPerMin:              20,
		RateLimitRefreshPerMin:            30,
		RateLimitAdminWritePerMin:         30,
		RateLimitAdminSyncPerMin:          10,
		RateLimitBurstMultiplier:          1.5,
		RateLimitSustainedWindow:          time.Minute,
		AuthAbuseFreeAttempts:             3,
		AuthAbuseBaseDelay:                2 * time.Second,
		AuthAbuseMultiplier:               2.0,
		AuthAbuseMaxDelay:                 5 * time.Minute,
		AuthAbuseResetWindow:              30 * time.Minute,
		RateLimitRedisEnabled:             true,
		IdempotencyEnabled:                true,
		IdempotencyRedisEnabled:           true,
		IdempotencyTTL:                    24 * time.Hour,
		RedisAddr:                         "localhost:6379",
		RedisDialTimeout:                  5 * time.Second,
		RedisReadTimeout:                  3 * time.Second,
		RedisWriteTimeout:                 3 * time.Second,
		RedisMaxRetries:                   3,
		RedisMinRetryBackoff:              8 * time.Millisecond,
		RedisMaxRetryBackoff:              512 * time.Millisecond,
		RedisPoolSize:                     10,
		RedisMinIdleConns:                 11,
		RedisPoolTimeout:                  4 * time.Second,
		CookieSecure:                      false,
		CookieSameSite:                    "none",
		OTELTraceSamplingRatio:            1.0,
		OTELMetricsExportInterval:         10 * time.Second,
		OTELLogLevel:                      "info",
		ReadinessProbeTimeout:             1 * time.Second,
		ShutdownTimeout:                   20 * time.Second,
		ShutdownHTTPDrainTimeout:          10 * time.Second,
		ShutdownObservabilityTimeout:      8 * time.Second,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when REDIS_MIN_IDLE_CONNS > REDIS_POOL_SIZE")
	}

	cfg.RedisMinIdleConns = 2
	cfg.RedisMaxRetryBackoff = 4 * time.Millisecond
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when REDIS_MAX_RETRY_BACKOFF < REDIS_MIN_RETRY_BACKOFF")
	}
}

func TestValidateNonLocalRedisRequiresACLAndTLS(t *testing.T) {
	cfg := &Config{
		Env:                               "qa",
		DatabaseURL:                       "postgres://x",
		JWTAccessSecret:                   "abcdefghijklmnopqrstuvwxyz123456",
		JWTRefreshSecret:                  "abcdefghijklmnopqrstuvwxyz654321",
		RefreshTokenPepper:                "pepper-1234567890",
		StateSigningSecret:                "state-secret-12345",
		AuthLocalEnabled:                  true,
		AuthGoogleEnabled:                 false,
		JWTAccessTTL:                      15 * time.Minute,
		JWTRefreshTTL:                     24 * time.Hour,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		AuthPasswordForgotRateLimitPerMin: 5,
		RBACProtectedRoles:                []string{"admin", "user"},
		RBACProtectedPermissions:          []string{"roles:write", "permissions:write"},
		AuthRateLimitPerMin:               30,
		APIRateLimitPerMin:                120,
		RateLimitLoginPerMin:              20,
		RateLimitRefreshPerMin:            30,
		RateLimitAdminWritePerMin:         30,
		RateLimitAdminSyncPerMin:          10,
		RateLimitBurstMultiplier:          1.5,
		RateLimitSustainedWindow:          time.Minute,
		AuthAbuseFreeAttempts:             3,
		AuthAbuseBaseDelay:                2 * time.Second,
		AuthAbuseMultiplier:               2.0,
		AuthAbuseMaxDelay:                 5 * time.Minute,
		AuthAbuseResetWindow:              30 * time.Minute,
		RateLimitRedisEnabled:             true,
		IdempotencyEnabled:                true,
		IdempotencyRedisEnabled:           true,
		IdempotencyTTL:                    24 * time.Hour,
		RedisAddr:                         "redis.internal:6379",
		RedisDialTimeout:                  5 * time.Second,
		RedisReadTimeout:                  3 * time.Second,
		RedisWriteTimeout:                 3 * time.Second,
		RedisMaxRetries:                   3,
		RedisMinRetryBackoff:              8 * time.Millisecond,
		RedisMaxRetryBackoff:              512 * time.Millisecond,
		RedisPoolSize:                     10,
		RedisMinIdleConns:                 2,
		RedisPoolTimeout:                  4 * time.Second,
		CookieSecure:                      false,
		CookieSameSite:                    "none",
		OTELTraceSamplingRatio:            1.0,
		OTELMetricsExportInterval:         10 * time.Second,
		OTELLogLevel:                      "info",
		ReadinessProbeTimeout:             1 * time.Second,
		ShutdownTimeout:                   20 * time.Second,
		ShutdownHTTPDrainTimeout:          10 * time.Second,
		ShutdownObservabilityTimeout:      8 * time.Second,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when non-local redis acl/tls settings are missing")
	}

	cfg.RedisUsername = "svc-app"
	cfg.RedisPassword = "secret-password"
	cfg.RedisTLSEnabled = true
	cfg.RedisTLSServerName = "redis.internal"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected non-local redis validation to pass with acl+tls: %v", err)
	}

	cfg.RedisTLSInsecureSkipVerify = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when REDIS_TLS_INSECURE_SKIP_VERIFY=true in non-local env")
	}
}

func TestValidateRedisNamespacePattern(t *testing.T) {
	cfg := &Config{
		Env:                               "development",
		DatabaseURL:                       "postgres://x",
		JWTAccessSecret:                   "abcdefghijklmnopqrstuvwxyz123456",
		JWTRefreshSecret:                  "abcdefghijklmnopqrstuvwxyz654321",
		RefreshTokenPepper:                "pepper-1234567890",
		StateSigningSecret:                "state-secret-12345",
		AuthLocalEnabled:                  true,
		AuthGoogleEnabled:                 false,
		JWTAccessTTL:                      15 * time.Minute,
		JWTRefreshTTL:                     24 * time.Hour,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		AuthPasswordForgotRateLimitPerMin: 5,
		RBACProtectedRoles:                []string{"admin", "user"},
		RBACProtectedPermissions:          []string{"roles:write", "permissions:write"},
		AuthRateLimitPerMin:               30,
		APIRateLimitPerMin:                120,
		RateLimitLoginPerMin:              20,
		RateLimitRefreshPerMin:            30,
		RateLimitAdminWritePerMin:         30,
		RateLimitAdminSyncPerMin:          10,
		RateLimitBurstMultiplier:          1.5,
		RateLimitSustainedWindow:          time.Minute,
		AuthAbuseFreeAttempts:             3,
		AuthAbuseBaseDelay:                2 * time.Second,
		AuthAbuseMultiplier:               2.0,
		AuthAbuseMaxDelay:                 5 * time.Minute,
		AuthAbuseResetWindow:              30 * time.Minute,
		RateLimitRedisEnabled:             true,
		IdempotencyEnabled:                true,
		IdempotencyRedisEnabled:           true,
		IdempotencyTTL:                    24 * time.Hour,
		RedisKeyNamespace:                 "v1:bad",
		RedisAddr:                         "localhost:6379",
		RedisDialTimeout:                  5 * time.Second,
		RedisReadTimeout:                  3 * time.Second,
		RedisWriteTimeout:                 3 * time.Second,
		RedisMaxRetries:                   3,
		RedisMinRetryBackoff:              8 * time.Millisecond,
		RedisMaxRetryBackoff:              512 * time.Millisecond,
		RedisPoolSize:                     10,
		RedisMinIdleConns:                 2,
		RedisPoolTimeout:                  4 * time.Second,
		CookieSecure:                      false,
		CookieSameSite:                    "none",
		OTELTraceSamplingRatio:            1.0,
		OTELMetricsExportInterval:         10 * time.Second,
		OTELLogLevel:                      "info",
		ReadinessProbeTimeout:             1 * time.Second,
		ShutdownTimeout:                   20 * time.Second,
		ShutdownHTTPDrainTimeout:          10 * time.Second,
		ShutdownObservabilityTimeout:      8 * time.Second,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid REDIS_KEY_NAMESPACE")
	}

	cfg.RedisKeyNamespace = "v2"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid REDIS_KEY_NAMESPACE to pass validation: %v", err)
	}
}

func TestValidateIdempotencyDBCleanupSettings(t *testing.T) {
	cfg := newValidConfigForProfileTests()
	cfg.IdempotencyEnabled = true
	cfg.IdempotencyRedisEnabled = false
	cfg.IdempotencyDBCleanupEnabled = true
	cfg.IdempotencyDBCleanupInterval = 500 * time.Millisecond
	cfg.IdempotencyDBCleanupBatch = 100

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when IDEMPOTENCY_DB_CLEANUP_INTERVAL is below 1s")
	}

	cfg.IdempotencyDBCleanupInterval = 5 * time.Minute
	cfg.IdempotencyDBCleanupBatch = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when IDEMPOTENCY_DB_CLEANUP_BATCH_SIZE is below 1")
	}

	cfg.IdempotencyDBCleanupBatch = 500
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid idempotency db cleanup config: %v", err)
	}
}

func TestValidateRateLimitRedisOutagePolicies(t *testing.T) {
	cfg := newValidConfigForProfileTests()
	cfg.RateLimitOutagePolicyAPI = "fail_open"
	cfg.RateLimitOutagePolicyAuth = "fail_closed"
	cfg.RateLimitOutagePolicyForgot = "fail_open"
	cfg.RateLimitOutagePolicyLogin = "fail_closed"
	cfg.RateLimitOutagePolicyRefresh = "fail_open"
	cfg.RateLimitOutagePolicyAdminW = "fail_closed"
	cfg.RateLimitOutagePolicyAdminS = "fail_closed"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid outage policies to pass validation: %v", err)
	}

	cfg.RateLimitOutagePolicyRefresh = "drop_requests"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid redis outage policy")
	}
}

func newValidConfigForProfileTests() *Config {
	return &Config{
		Env:                               "development",
		DatabaseURL:                       "postgres://x",
		JWTAccessSecret:                   "abcdefghijklmnopqrstuvwxyz123456",
		JWTRefreshSecret:                  "abcdefghijklmnopqrstuvwxyz654321",
		RefreshTokenPepper:                "pepper-1234567890",
		StateSigningSecret:                "state-secret-12345",
		AuthLocalEnabled:                  true,
		AuthGoogleEnabled:                 false,
		JWTAccessTTL:                      15 * time.Minute,
		JWTRefreshTTL:                     24 * time.Hour,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		AuthPasswordForgotRateLimitPerMin: 5,
		RBACProtectedRoles:                []string{"admin", "user"},
		RBACProtectedPermissions:          []string{"roles:write", "permissions:write"},
		AuthRateLimitPerMin:               30,
		APIRateLimitPerMin:                120,
		RateLimitLoginPerMin:              20,
		RateLimitRefreshPerMin:            30,
		RateLimitAdminWritePerMin:         30,
		RateLimitAdminSyncPerMin:          10,
		RateLimitBurstMultiplier:          1.5,
		RateLimitSustainedWindow:          time.Minute,
		AuthAbuseFreeAttempts:             3,
		AuthAbuseBaseDelay:                2 * time.Second,
		AuthAbuseMultiplier:               2.0,
		AuthAbuseMaxDelay:                 5 * time.Minute,
		AuthAbuseResetWindow:              30 * time.Minute,
		RateLimitRedisEnabled:             true,
		IdempotencyEnabled:                true,
		IdempotencyRedisEnabled:           true,
		IdempotencyTTL:                    24 * time.Hour,
		RedisAddr:                         "localhost:6379",
		RedisDialTimeout:                  5 * time.Second,
		RedisReadTimeout:                  3 * time.Second,
		RedisWriteTimeout:                 3 * time.Second,
		RedisMaxRetries:                   3,
		RedisMinRetryBackoff:              8 * time.Millisecond,
		RedisMaxRetryBackoff:              512 * time.Millisecond,
		RedisPoolSize:                     10,
		RedisMinIdleConns:                 2,
		RedisPoolTimeout:                  4 * time.Second,
		CookieSecure:                      false,
		CookieSameSite:                    "none",
		OTELTraceSamplingRatio:            1.0,
		OTELMetricsExportInterval:         10 * time.Second,
		OTELLogLevel:                      "info",
		ReadinessProbeTimeout:             1 * time.Second,
		ShutdownTimeout:                   20 * time.Second,
		ShutdownHTTPDrainTimeout:          10 * time.Second,
		ShutdownObservabilityTimeout:      8 * time.Second,
	}
}
