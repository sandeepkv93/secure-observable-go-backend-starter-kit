package observability

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/config"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestRecordMetricHelpersNoPanicWhenUninitialized(t *testing.T) {
	ctx := context.Background()
	metricsMu.Lock()
	appMetrics = nil
	metricsMu.Unlock()

	// Smoke-call every helper with appMetrics=nil; they should all no-op safely.
	RecordAuthLogin(ctx, "local", "success")
	RecordAuthRefresh(ctx, "success")
	RecordAuthLogout(ctx, "success")
	RecordAdminRBACMutation(ctx, "role", "update", "success")
	RecordAdminRoleMutation(ctx, "create")
	RecordAdminListCacheEvent(ctx, "roles", "hit")
	RecordRBACPermissionCacheEvent(ctx, "miss")
	RecordIdempotencyEvent(ctx, "register", "new")
	RecordAuthRequestDuration(ctx, "login", "success", 10*time.Millisecond)
	RecordAccessTokenValidation(ctx, "ok", "header")
	RecordCSRFValidation(ctx, "ok", "auth")
	RecordRateLimitDecision(ctx, "login", "allow", "distributed", "subject")
	RecordRateLimitRetryAfter(ctx, "login", "burst", time.Second)
	RecordAuthAbuseGuardEvent(ctx, "login", "check", "ok")
	RecordAuthAbuseCooldown(ctx, "login", "check", time.Second)
	RecordRefreshSecurityEvent(ctx, "ok")
	RecordSessionManagementEvent(ctx, "revoke", "success")
	RecordSessionRevokedCount(ctx, "revoke_others", 2)
	RecordUserProfileEvent(ctx, "success")
	RecordAuthLocalFlowEvent(ctx, "forgot_password", "accepted")
	RecordAdminListRequestDuration(ctx, "roles", "success", 20*time.Millisecond)
	RecordAdminListPageSize(ctx, "roles", 25)
	RecordHealthCheckResult(ctx, "db", "ready")
	RecordHealthCheckDuration(ctx, "db", 5*time.Millisecond)
	RecordDatabaseStartupEvent(ctx, "connect", "success")
	RecordDatabaseStartupDuration(ctx, "migrate", 15*time.Millisecond)
	RecordIdempotencyCleanupRun(ctx, "success")
	RecordIdempotencyCleanupDeletedRows(ctx, 3)
	RecordRepositoryOperation(ctx, "user", "list", "success")
	RecordToolCommandRun(ctx, "migrate", "up", "success")
	RecordToolCommandDuration(ctx, "seed", "run", "success", 30*time.Millisecond)
	RecordLoadgenRequest(ctx, "2xx", "baseline")
	RecordObscheckStageEvent(ctx, "traces", "pass")
	RecordGoogleOAuthRequestDuration(ctx, "exchange", "success", 12*time.Millisecond)
	RecordGoogleOAuthError(ctx, "token_exchange")
	RecordRBACAuthorizationEvent(ctx, "users:read", "allow")
	RecordSecurityBypassEvent(ctx, "trusted_subnet", "login")
	RecordAdminRBACSyncReport(ctx, "created_roles", 2)
	RecordMiddlewareValidationEvent(ctx, "csrf", "pass")
	RecordAdminListCacheEntryAge(ctx, "roles", 2*time.Second)
	RecordAdminNegativeLookupEffectiveness(ctx, "hit")
}

func TestRecordMetricHelpersEmitExpectedLabelCardinality(t *testing.T) {
	ctx := context.Background()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() { _ = provider.Shutdown(ctx) }()

	m := newTestAppMetrics(t, provider)
	metricsMu.Lock()
	appMetrics = m
	metricsMu.Unlock()
	defer func() {
		metricsMu.Lock()
		appMetrics = nil
		metricsMu.Unlock()
	}()

	RecordAuthLogin(ctx, "local", "success")
	RecordAuthRefresh(ctx, "success")
	RecordAuthLogout(ctx, "success")
	RecordAdminRBACMutation(ctx, "role", "update", "success")
	RecordAdminRoleMutation(ctx, "create")
	RecordAdminListCacheEvent(ctx, "roles", "hit")
	RecordRBACPermissionCacheEvent(ctx, "miss")
	RecordIdempotencyEvent(ctx, "register", "new")
	RecordAuthRequestDuration(ctx, "login", "success", 10*time.Millisecond)
	RecordAccessTokenValidation(ctx, "ok", "header")
	RecordCSRFValidation(ctx, "ok", "auth")
	RecordRateLimitDecision(ctx, "login", "allow", "distributed", "subject")
	RecordRateLimitRetryAfter(ctx, "login", "burst", time.Second)
	RecordAuthAbuseGuardEvent(ctx, "login", "check", "ok")
	RecordAuthAbuseCooldown(ctx, "login", "check", time.Second)
	RecordRefreshSecurityEvent(ctx, "ok")
	RecordSessionManagementEvent(ctx, "revoke", "success")
	RecordSessionRevokedCount(ctx, "revoke_others", 2)
	RecordUserProfileEvent(ctx, "success")
	RecordAuthLocalFlowEvent(ctx, "forgot_password", "accepted")
	RecordAdminListRequestDuration(ctx, "roles", "success", 20*time.Millisecond)
	RecordAdminListPageSize(ctx, "roles", 25)
	RecordHealthCheckResult(ctx, "db", "ready")
	RecordHealthCheckDuration(ctx, "db", 5*time.Millisecond)
	RecordDatabaseStartupEvent(ctx, "connect", "success")
	RecordDatabaseStartupDuration(ctx, "migrate", 15*time.Millisecond)
	RecordIdempotencyCleanupRun(ctx, "success")
	RecordIdempotencyCleanupDeletedRows(ctx, 3)
	RecordRepositoryOperation(ctx, "user", "list", "success")
	RecordToolCommandRun(ctx, "migrate", "up", "success")
	RecordToolCommandDuration(ctx, "seed", "run", "success", 30*time.Millisecond)
	RecordLoadgenRequest(ctx, "2xx", "baseline")
	RecordObscheckStageEvent(ctx, "traces", "pass")
	RecordGoogleOAuthRequestDuration(ctx, "exchange", "success", 12*time.Millisecond)
	RecordGoogleOAuthError(ctx, "token_exchange")
	RecordRBACAuthorizationEvent(ctx, "users:read", "allow")
	RecordSecurityBypassEvent(ctx, "trusted_subnet", "login")
	RecordAdminRBACSyncReport(ctx, "created_roles", 2)
	RecordMiddlewareValidationEvent(ctx, "csrf", "pass")
	RecordAdminListCacheEntryAge(ctx, "roles", 2*time.Second)
	RecordAdminNegativeLookupEffectiveness(ctx, "hit")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}

	expected := map[string]int{
		"auth.login.attempts":                 2,
		"auth.refresh.attempts":               1,
		"auth.logout.attempts":                1,
		"admin.rbac.mutations":                3,
		"admin.list.cache.events":             2,
		"auth.rbac.permission.cache.events":   1,
		"http.idempotency.events":             2,
		"auth.request.duration":               2,
		"auth.access_token.validation.events": 2,
		"security.csrf.validation.events":     2,
		"http.rate_limit.decisions":           4,
		"http.rate_limit.retry_after":         2,
		"auth.abuse_guard.events":             3,
		"auth.abuse_guard.cooldown":           2,
		"auth.refresh.security.events":        1,
		"session.management.events":           2,
		"session.revoked.count":               1,
		"user.profile.events":                 1,
		"auth.local.flow.events":              2,
		"admin.list.request.duration":         2,
		"admin.list.page_size":                1,
		"health.check.results":                2,
		"health.check.duration":               1,
		"database.startup.events":             2,
		"database.startup.duration":           1,
		"idempotency.cleanup.runs":            1,
		"idempotency.cleanup.deleted_rows":    0,
		"repository.operations":               3,
		"tool.command.runs":                   3,
		"tool.command.duration":               3,
		"loadgen.requests":                    2,
		"obscheck.stage.events":               2,
		"auth.oauth.google.request.duration":  2,
		"auth.oauth.google.errors":            1,
		"auth.rbac.authorization.events":      2,
		"security.bypass.events":              2,
		"admin.rbac.sync.report":              1,
		"http.middleware.validation.events":   2,
		"admin.list.cache.entry_age":          1,
		"admin.lookup.negative.effectiveness": 1,
	}

	observed := collectLabelCardinality(t, rm)
	for metricName, want := range expected {
		got, ok := observed[metricName]
		if !ok {
			t.Fatalf("missing metric datapoint for %s", metricName)
		}
		if got != want {
			t.Fatalf("metric %s label cardinality mismatch: got=%d want=%d", metricName, got, want)
		}
	}
}

func TestInitMetricsDisabledReturnsProvider(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{OTELMetricsEnabled: false}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	mp, err := InitMetrics(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("init metrics disabled: %v", err)
	}
	if mp == nil {
		t.Fatal("expected non-nil meter provider")
	}
	_ = mp.Shutdown(ctx)
}

func newTestAppMetrics(t *testing.T, provider *sdkmetric.MeterProvider) *AppMetrics {
	t.Helper()
	meter := provider.Meter("observability-test")

	counter := func(name string) metric.Int64Counter {
		t.Helper()
		c, err := meter.Int64Counter(name)
		if err != nil {
			t.Fatalf("create counter %s: %v", name, err)
		}
		return c
	}
	hist := func(name string) metric.Float64Histogram {
		t.Helper()
		h, err := meter.Float64Histogram(name)
		if err != nil {
			t.Fatalf("create histogram %s: %v", name, err)
		}
		return h
	}

	return &AppMetrics{
		authLoginCounter:             counter("auth.login.attempts"),
		authRefreshCounter:           counter("auth.refresh.attempts"),
		authLogoutCounter:            counter("auth.logout.attempts"),
		adminRBACCounter:             counter("admin.rbac.mutations"),
		adminListCacheHits:           counter("admin.list.cache.events"),
		rbacCacheCounter:             counter("auth.rbac.permission.cache.events"),
		idempotencyCounter:           counter("http.idempotency.events"),
		authReqDuration:              hist("auth.request.duration"),
		accessTokenValidationCounter: counter("auth.access_token.validation.events"),
		csrfValidationCounter:        counter("security.csrf.validation.events"),
		rateLimitDecisionCounter:     counter("http.rate_limit.decisions"),
		rateLimitRetryAfter:          hist("http.rate_limit.retry_after"),
		abuseGuardCounter:            counter("auth.abuse_guard.events"),
		abuseGuardCooldown:           hist("auth.abuse_guard.cooldown"),
		refreshSecurityCounter:       counter("auth.refresh.security.events"),
		sessionManagementCounter:     counter("session.management.events"),
		sessionRevokedCount:          hist("session.revoked.count"),
		userProfileCounter:           counter("user.profile.events"),
		authLocalFlowCounter:         counter("auth.local.flow.events"),
		adminListReqDuration:         hist("admin.list.request.duration"),
		adminListPageSize:            hist("admin.list.page_size"),
		healthCheckResultCounter:     counter("health.check.results"),
		healthCheckDuration:          hist("health.check.duration"),
		databaseStartupCounter:       counter("database.startup.events"),
		databaseStartupDuration:      hist("database.startup.duration"),
		idempotencyCleanupCounter:    counter("idempotency.cleanup.runs"),
		idempotencyCleanupDeleted:    hist("idempotency.cleanup.deleted_rows"),
		repositoryOpsCounter:         counter("repository.operations"),
		toolCommandRuns:              counter("tool.command.runs"),
		toolCommandDuration:          hist("tool.command.duration"),
		loadgenRequestsCounter:       counter("loadgen.requests"),
		obscheckStageCounter:         counter("obscheck.stage.events"),
		oauthGoogleReqDuration:       hist("auth.oauth.google.request.duration"),
		oauthGoogleErrorsCounter:     counter("auth.oauth.google.errors"),
		rbacAuthorizationCounter:     counter("auth.rbac.authorization.events"),
		securityBypassCounter:        counter("security.bypass.events"),
		adminRBACSyncReport:          hist("admin.rbac.sync.report"),
		httpMiddlewareValidation:     counter("http.middleware.validation.events"),
		adminListCacheEntryAge:       hist("admin.list.cache.entry_age"),
		adminNegativeLookupCounter:   counter("admin.lookup.negative.effectiveness"),
		productOperationCounter:      counter("product.operation.events"),
		productOperationDuration:     hist("product.operation.duration"),
	}
}

func collectLabelCardinality(t *testing.T, rm metricdata.ResourceMetrics) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				if len(data.DataPoints) > 0 {
					out[m.Name] = data.DataPoints[0].Attributes.Len()
				}
			case metricdata.Sum[float64]:
				if len(data.DataPoints) > 0 {
					out[m.Name] = data.DataPoints[0].Attributes.Len()
				}
			case metricdata.Histogram[int64]:
				if len(data.DataPoints) > 0 {
					out[m.Name] = data.DataPoints[0].Attributes.Len()
				}
			case metricdata.Histogram[float64]:
				if len(data.DataPoints) > 0 {
					out[m.Name] = data.DataPoints[0].Attributes.Len()
				}
			}
		}
	}
	return out
}
