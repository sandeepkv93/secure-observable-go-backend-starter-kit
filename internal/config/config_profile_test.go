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
