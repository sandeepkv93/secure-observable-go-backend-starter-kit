package observability

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/config"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
	"go.opentelemetry.io/otel/sdk/resource"
)

type AppMetrics struct {
	authLoginCounter             metric.Int64Counter
	authRefreshCounter           metric.Int64Counter
	authLogoutCounter            metric.Int64Counter
	adminRBACCounter             metric.Int64Counter
	adminListCacheHits           metric.Int64Counter
	rbacCacheCounter             metric.Int64Counter
	idempotencyCounter           metric.Int64Counter
	authReqDuration              metric.Float64Histogram
	accessTokenValidationCounter metric.Int64Counter
	csrfValidationCounter        metric.Int64Counter
	rateLimitDecisionCounter     metric.Int64Counter
	rateLimitRetryAfter          metric.Float64Histogram
	abuseGuardCounter            metric.Int64Counter
	abuseGuardCooldown           metric.Float64Histogram
	refreshSecurityCounter       metric.Int64Counter
	sessionManagementCounter     metric.Int64Counter
	sessionRevokedCount          metric.Float64Histogram
	userProfileCounter           metric.Int64Counter
	authLocalFlowCounter         metric.Int64Counter
	adminListReqDuration         metric.Float64Histogram
	adminListPageSize            metric.Float64Histogram
	healthCheckResultCounter     metric.Int64Counter
	healthCheckDuration          metric.Float64Histogram
	databaseStartupCounter       metric.Int64Counter
	databaseStartupDuration      metric.Float64Histogram
	idempotencyCleanupCounter    metric.Int64Counter
	idempotencyCleanupDeleted    metric.Float64Histogram
	repositoryOpsCounter         metric.Int64Counter
	toolCommandRuns              metric.Int64Counter
	toolCommandDuration          metric.Float64Histogram
	loadgenRequestsCounter       metric.Int64Counter
	obscheckStageCounter         metric.Int64Counter
	oauthGoogleReqDuration       metric.Float64Histogram
	oauthGoogleErrorsCounter     metric.Int64Counter
	rbacAuthorizationCounter     metric.Int64Counter
	securityBypassCounter        metric.Int64Counter
	adminRBACSyncReport          metric.Float64Histogram
	httpMiddlewareValidation     metric.Int64Counter
	adminListCacheEntryAge       metric.Float64Histogram
	adminNegativeLookupCounter   metric.Int64Counter
	featureFlagEvalCounter       metric.Int64Counter
	featureFlagEvalDuration      metric.Float64Histogram
	featureFlagCacheCounter      metric.Int64Counter
	productOperationCounter      metric.Int64Counter
	productOperationDuration     metric.Float64Histogram
}

var (
	metricsMu  sync.RWMutex
	appMetrics *AppMetrics
)

func InitMetrics(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*sdkmetric.MeterProvider, error) {
	if !cfg.OTELMetricsEnabled {
		mp := sdkmetric.NewMeterProvider()
		otel.SetMeterProvider(mp)
		logger.Info("otel metrics disabled")
		return mp, nil
	}

	opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(cfg.OTELExporterOTLPEndpoint)}
	if cfg.OTELExporterOTLPInsecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp metric exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", cfg.OTELServiceName),
			attribute.String("deployment.environment", cfg.OTELEnvironment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create metric resource: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(cfg.OTELMetricsExportInterval))
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
		sdkmetric.WithExemplarFilter(exemplar.TraceBasedFilter),
		sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{Name: "auth.request.duration"},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
				},
			},
		)),
	)
	otel.SetMeterProvider(mp)

	meter := mp.Meter("everything-backend-starter-kit")
	loginCounter, err := meter.Int64Counter("auth.login.attempts")
	if err != nil {
		return nil, err
	}
	refreshCounter, err := meter.Int64Counter("auth.refresh.attempts")
	if err != nil {
		return nil, err
	}
	logoutCounter, err := meter.Int64Counter("auth.logout.attempts")
	if err != nil {
		return nil, err
	}
	adminRBACCounter, err := meter.Int64Counter("admin.rbac.mutations")
	if err != nil {
		return nil, err
	}
	adminListCacheEvents, err := meter.Int64Counter("admin.list.cache.events")
	if err != nil {
		return nil, err
	}
	rbacPermissionCacheEvents, err := meter.Int64Counter("auth.rbac.permission.cache.events")
	if err != nil {
		return nil, err
	}
	idempotencyCounter, err := meter.Int64Counter("http.idempotency.events")
	if err != nil {
		return nil, err
	}
	authReqDuration, err := meter.Float64Histogram("auth.request.duration", metric.WithUnit("s"), metric.WithDescription("Duration of auth endpoint requests in seconds"))
	if err != nil {
		return nil, err
	}
	accessTokenValidationCounter, err := meter.Int64Counter("auth.access_token.validation.events")
	if err != nil {
		return nil, err
	}
	csrfValidationCounter, err := meter.Int64Counter("security.csrf.validation.events")
	if err != nil {
		return nil, err
	}
	rateLimitDecisionCounter, err := meter.Int64Counter("http.rate_limit.decisions")
	if err != nil {
		return nil, err
	}
	rateLimitRetryAfter, err := meter.Float64Histogram(
		"http.rate_limit.retry_after",
		metric.WithUnit("s"),
		metric.WithDescription("Retry-after duration in seconds for throttled requests"),
	)
	if err != nil {
		return nil, err
	}
	abuseGuardCounter, err := meter.Int64Counter("auth.abuse_guard.events")
	if err != nil {
		return nil, err
	}
	abuseGuardCooldown, err := meter.Float64Histogram(
		"auth.abuse_guard.cooldown",
		metric.WithUnit("s"),
		metric.WithDescription("Cooldown duration returned by auth abuse guard"),
	)
	if err != nil {
		return nil, err
	}
	refreshSecurityCounter, err := meter.Int64Counter("auth.refresh.security.events")
	if err != nil {
		return nil, err
	}
	sessionManagementCounter, err := meter.Int64Counter("session.management.events")
	if err != nil {
		return nil, err
	}
	sessionRevokedCount, err := meter.Float64Histogram(
		"session.revoked.count",
		metric.WithDescription("Number of sessions revoked per management action"),
	)
	if err != nil {
		return nil, err
	}
	userProfileCounter, err := meter.Int64Counter("user.profile.events")
	if err != nil {
		return nil, err
	}
	authLocalFlowCounter, err := meter.Int64Counter("auth.local.flow.events")
	if err != nil {
		return nil, err
	}
	adminListReqDuration, err := meter.Float64Histogram(
		"admin.list.request.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of admin list endpoint requests in seconds"),
	)
	if err != nil {
		return nil, err
	}
	adminListPageSize, err := meter.Float64Histogram(
		"admin.list.page_size",
		metric.WithDescription("Requested page size for admin list endpoints"),
	)
	if err != nil {
		return nil, err
	}
	healthCheckResultCounter, err := meter.Int64Counter("health.check.results")
	if err != nil {
		return nil, err
	}
	healthCheckDuration, err := meter.Float64Histogram(
		"health.check.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of health dependency checks in seconds"),
	)
	if err != nil {
		return nil, err
	}
	databaseStartupCounter, err := meter.Int64Counter("database.startup.events")
	if err != nil {
		return nil, err
	}
	databaseStartupDuration, err := meter.Float64Histogram(
		"database.startup.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of database startup phases in seconds"),
	)
	if err != nil {
		return nil, err
	}
	idempotencyCleanupCounter, err := meter.Int64Counter("idempotency.cleanup.runs")
	if err != nil {
		return nil, err
	}
	idempotencyCleanupDeleted, err := meter.Float64Histogram(
		"idempotency.cleanup.deleted_rows",
		metric.WithDescription("Deleted idempotency rows per cleanup run"),
	)
	if err != nil {
		return nil, err
	}
	repositoryOpsCounter, err := meter.Int64Counter("repository.operations")
	if err != nil {
		return nil, err
	}
	toolCommandRuns, err := meter.Int64Counter("tool.command.runs")
	if err != nil {
		return nil, err
	}
	toolCommandDuration, err := meter.Float64Histogram(
		"tool.command.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of tool command execution in seconds"),
	)
	if err != nil {
		return nil, err
	}
	loadgenRequestsCounter, err := meter.Int64Counter("loadgen.requests")
	if err != nil {
		return nil, err
	}
	obscheckStageCounter, err := meter.Int64Counter("obscheck.stage.events")
	if err != nil {
		return nil, err
	}
	oauthGoogleReqDuration, err := meter.Float64Histogram(
		"auth.oauth.google.request.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of Google OAuth provider operations in seconds"),
	)
	if err != nil {
		return nil, err
	}
	oauthGoogleErrorsCounter, err := meter.Int64Counter("auth.oauth.google.errors")
	if err != nil {
		return nil, err
	}
	rbacAuthorizationCounter, err := meter.Int64Counter("auth.rbac.authorization.events")
	if err != nil {
		return nil, err
	}
	securityBypassCounter, err := meter.Int64Counter("security.bypass.events")
	if err != nil {
		return nil, err
	}
	adminRBACSyncReport, err := meter.Float64Histogram(
		"admin.rbac.sync.report",
		metric.WithDescription("RBAC sync report counts by field"),
	)
	if err != nil {
		return nil, err
	}
	httpMiddlewareValidation, err := meter.Int64Counter("http.middleware.validation.events")
	if err != nil {
		return nil, err
	}
	adminListCacheEntryAge, err := meter.Float64Histogram(
		"admin.list.cache.entry_age",
		metric.WithUnit("s"),
		metric.WithDescription("Age in seconds of admin list cache entries at hit time"),
	)
	if err != nil {
		return nil, err
	}
	adminNegativeLookupCounter, err := meter.Int64Counter("admin.lookup.negative.effectiveness")
	if err != nil {
		return nil, err
	}
	featureFlagEvalCounter, err := meter.Int64Counter("feature_flag.evaluation.events")
	if err != nil {
		return nil, err
	}
	featureFlagEvalDuration, err := meter.Float64Histogram(
		"feature_flag.evaluation.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of feature flag evaluation operations in seconds"),
	)
	if err != nil {
		return nil, err
	}
	featureFlagCacheCounter, err := meter.Int64Counter("feature_flag.evaluation.cache.events")
	if err != nil {
		return nil, err
	}
	productOperationCounter, err := meter.Int64Counter("product.operation.events")
	if err != nil {
		return nil, err
	}
	productOperationDuration, err := meter.Float64Histogram(
		"product.operation.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of product business operations in seconds"),
	)
	if err != nil {
		return nil, err
	}

	metricsMu.Lock()
	appMetrics = &AppMetrics{
		authLoginCounter:             loginCounter,
		authRefreshCounter:           refreshCounter,
		authLogoutCounter:            logoutCounter,
		adminRBACCounter:             adminRBACCounter,
		adminListCacheHits:           adminListCacheEvents,
		rbacCacheCounter:             rbacPermissionCacheEvents,
		idempotencyCounter:           idempotencyCounter,
		authReqDuration:              authReqDuration,
		accessTokenValidationCounter: accessTokenValidationCounter,
		csrfValidationCounter:        csrfValidationCounter,
		rateLimitDecisionCounter:     rateLimitDecisionCounter,
		rateLimitRetryAfter:          rateLimitRetryAfter,
		abuseGuardCounter:            abuseGuardCounter,
		abuseGuardCooldown:           abuseGuardCooldown,
		refreshSecurityCounter:       refreshSecurityCounter,
		sessionManagementCounter:     sessionManagementCounter,
		sessionRevokedCount:          sessionRevokedCount,
		userProfileCounter:           userProfileCounter,
		authLocalFlowCounter:         authLocalFlowCounter,
		adminListReqDuration:         adminListReqDuration,
		adminListPageSize:            adminListPageSize,
		healthCheckResultCounter:     healthCheckResultCounter,
		healthCheckDuration:          healthCheckDuration,
		databaseStartupCounter:       databaseStartupCounter,
		databaseStartupDuration:      databaseStartupDuration,
		idempotencyCleanupCounter:    idempotencyCleanupCounter,
		idempotencyCleanupDeleted:    idempotencyCleanupDeleted,
		repositoryOpsCounter:         repositoryOpsCounter,
		toolCommandRuns:              toolCommandRuns,
		toolCommandDuration:          toolCommandDuration,
		loadgenRequestsCounter:       loadgenRequestsCounter,
		obscheckStageCounter:         obscheckStageCounter,
		oauthGoogleReqDuration:       oauthGoogleReqDuration,
		oauthGoogleErrorsCounter:     oauthGoogleErrorsCounter,
		rbacAuthorizationCounter:     rbacAuthorizationCounter,
		securityBypassCounter:        securityBypassCounter,
		adminRBACSyncReport:          adminRBACSyncReport,
		httpMiddlewareValidation:     httpMiddlewareValidation,
		adminListCacheEntryAge:       adminListCacheEntryAge,
		adminNegativeLookupCounter:   adminNegativeLookupCounter,
		featureFlagEvalCounter:       featureFlagEvalCounter,
		featureFlagEvalDuration:      featureFlagEvalDuration,
		featureFlagCacheCounter:      featureFlagCacheCounter,
		productOperationCounter:      productOperationCounter,
		productOperationDuration:     productOperationDuration,
	}
	metricsMu.Unlock()

	logger.Info("otel metrics initialized", "endpoint", cfg.OTELExporterOTLPEndpoint)
	return mp, nil
}

func RecordAuthLogin(ctx context.Context, provider, status string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.authLoginCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("provider", provider),
			attribute.String("status", status),
		),
	)
}

func RecordAuthRefresh(ctx context.Context, status string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.authRefreshCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("status", status)))
}

func RecordAuthLogout(ctx context.Context, status string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.authLogoutCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("status", status)))
}

func RecordAdminRBACMutation(ctx context.Context, entity, action, status string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.adminRBACCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("entity", entity),
		attribute.String("action", action),
		attribute.String("status", status),
	))
}

func RecordAdminRoleMutation(ctx context.Context, action string) {
	RecordAdminRBACMutation(ctx, "role", action, "success")
}

func RecordAdminListCacheEvent(ctx context.Context, endpoint, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.adminListCacheHits.Add(ctx, 1, metric.WithAttributes(
		attribute.String("endpoint", endpoint),
		attribute.String("outcome", outcome),
	))
}

func RecordRBACPermissionCacheEvent(ctx context.Context, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.rbacCacheCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

func RecordIdempotencyEvent(ctx context.Context, scope, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.idempotencyCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("scope", scope),
		attribute.String("outcome", outcome),
	))
}

func RecordAuthRequestDuration(ctx context.Context, endpoint, status string, duration time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.authReqDuration.Record(
		ctx,
		duration.Seconds(),
		metric.WithAttributes(
			attribute.String("endpoint", endpoint),
			attribute.String("status", status),
		),
	)
}

func RecordAccessTokenValidation(ctx context.Context, outcome, source string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.accessTokenValidationCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
		attribute.String("source", source),
	))
}

func RecordCSRFValidation(ctx context.Context, outcome, pathGroup string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.csrfValidationCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
		attribute.String("path_group", pathGroup),
	))
}

func RecordRateLimitDecision(ctx context.Context, scope, outcome, mode, keyType string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.rateLimitDecisionCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("scope", scope),
		attribute.String("outcome", outcome),
		attribute.String("mode", mode),
		attribute.String("key_type", keyType),
	))
}

func RecordRateLimitRetryAfter(ctx context.Context, scope, reason string, retryAfter time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.rateLimitRetryAfter.Record(ctx, retryAfter.Seconds(), metric.WithAttributes(
		attribute.String("scope", scope),
		attribute.String("reason", reason),
	))
}

func RecordAuthAbuseGuardEvent(ctx context.Context, scope, action, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.abuseGuardCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("scope", scope),
		attribute.String("action", action),
		attribute.String("outcome", outcome),
	))
}

func RecordAuthAbuseCooldown(ctx context.Context, scope, action string, cooldown time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.abuseGuardCooldown.Record(ctx, cooldown.Seconds(), metric.WithAttributes(
		attribute.String("scope", scope),
		attribute.String("action", action),
	))
}

func RecordRefreshSecurityEvent(ctx context.Context, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.refreshSecurityCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

func RecordSessionManagementEvent(ctx context.Context, action, status string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.sessionManagementCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("action", action),
		attribute.String("status", status),
	))
}

func RecordSessionRevokedCount(ctx context.Context, action string, count int64) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.sessionRevokedCount.Record(ctx, float64(count), metric.WithAttributes(
		attribute.String("action", action),
	))
}

func RecordUserProfileEvent(ctx context.Context, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.userProfileCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

func RecordAuthLocalFlowEvent(ctx context.Context, flow, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.authLocalFlowCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("flow", flow),
		attribute.String("outcome", outcome),
	))
}

func RecordAdminListRequestDuration(ctx context.Context, endpoint, status string, duration time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.adminListReqDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("endpoint", endpoint),
		attribute.String("status", status),
	))
}

func RecordAdminListPageSize(ctx context.Context, endpoint string, pageSize int) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.adminListPageSize.Record(ctx, float64(pageSize), metric.WithAttributes(
		attribute.String("endpoint", endpoint),
	))
}

func RecordHealthCheckResult(ctx context.Context, check, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.healthCheckResultCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("check", check),
		attribute.String("outcome", outcome),
	))
}

func RecordHealthCheckDuration(ctx context.Context, check string, duration time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.healthCheckDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("check", check),
	))
}

func RecordDatabaseStartupEvent(ctx context.Context, phase, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.databaseStartupCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("phase", phase),
		attribute.String("outcome", outcome),
	))
}

func RecordDatabaseStartupDuration(ctx context.Context, phase string, duration time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.databaseStartupDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("phase", phase),
	))
}

func RecordIdempotencyCleanupRun(ctx context.Context, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.idempotencyCleanupCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

func RecordIdempotencyCleanupDeletedRows(ctx context.Context, deleted int64) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.idempotencyCleanupDeleted.Record(ctx, float64(deleted))
}

func RecordRepositoryOperation(ctx context.Context, repo, op, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.repositoryOpsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("repo", repo),
		attribute.String("op", op),
		attribute.String("outcome", outcome),
	))
}

func RecordToolCommandRun(ctx context.Context, tool, command, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.toolCommandRuns.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tool", tool),
		attribute.String("command", command),
		attribute.String("outcome", outcome),
	))
}

func RecordToolCommandDuration(ctx context.Context, tool, command, outcome string, duration time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.toolCommandDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("tool", tool),
		attribute.String("command", command),
		attribute.String("outcome", outcome),
	))
}

func RecordLoadgenRequest(ctx context.Context, statusClass, profile string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.loadgenRequestsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("status_class", statusClass),
		attribute.String("profile", profile),
	))
}

func RecordObscheckStageEvent(ctx context.Context, stage, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.obscheckStageCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("stage", stage),
		attribute.String("outcome", outcome),
	))
}

func RecordGoogleOAuthRequestDuration(ctx context.Context, operation, status string, duration time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.oauthGoogleReqDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("status", status),
	))
}

func RecordGoogleOAuthError(ctx context.Context, errorClass string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.oauthGoogleErrorsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("error_class", errorClass),
	))
}

func RecordRBACAuthorizationEvent(ctx context.Context, requiredPermission, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.rbacAuthorizationCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("required_permission", requiredPermission),
		attribute.String("outcome", outcome),
	))
}

func RecordSecurityBypassEvent(ctx context.Context, reason, scope string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.securityBypassCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("reason", reason),
		attribute.String("scope", scope),
	))
}

func RecordAdminRBACSyncReport(ctx context.Context, field string, value float64) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.adminRBACSyncReport.Record(ctx, value, metric.WithAttributes(
		attribute.String("field", field),
	))
}

func RecordMiddlewareValidationEvent(ctx context.Context, middleware, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.httpMiddlewareValidation.Add(ctx, 1, metric.WithAttributes(
		attribute.String("middleware", middleware),
		attribute.String("outcome", outcome),
	))
}

func RecordAdminListCacheEntryAge(ctx context.Context, namespace string, age time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.adminListCacheEntryAge.Record(ctx, age.Seconds(), metric.WithAttributes(
		attribute.String("namespace", namespace),
	))
}

func RecordAdminNegativeLookupEffectiveness(ctx context.Context, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.adminNegativeLookupCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

func RecordFeatureFlagEvaluation(ctx context.Context, mode, outcome string, duration time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.featureFlagEvalCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("mode", mode),
		attribute.String("outcome", outcome),
	))
	m.featureFlagEvalDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("mode", mode),
		attribute.String("outcome", outcome),
	))
}

func RecordFeatureFlagEvaluationCache(ctx context.Context, outcome string) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.featureFlagCacheCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

func RecordProductOperation(ctx context.Context, operation, outcome string, duration time.Duration) {
	metricsMu.RLock()
	m := appMetrics
	metricsMu.RUnlock()
	if m == nil {
		return
	}
	m.productOperationCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("outcome", outcome),
	))
	m.productOperationDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("outcome", outcome),
	))
}
