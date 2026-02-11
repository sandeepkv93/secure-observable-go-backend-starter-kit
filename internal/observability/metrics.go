package observability

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"

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

	meter := mp.Meter("secure-observable-go-backend-starter-kit")
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
