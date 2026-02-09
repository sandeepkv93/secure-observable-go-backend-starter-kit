package observability

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func InitTracing(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*sdktrace.TracerProvider, error) {
	if !cfg.OTELTracingEnabled {
		tp := sdktrace.NewTracerProvider()
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
		logger.Info("otel tracing disabled")
		return tp, nil
	}

	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(cfg.OTELExporterOTLPEndpoint)}
	if cfg.OTELExporterOTLPInsecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp trace exporter: %w", err)
	}

	res, err := sdkresource.New(ctx,
		sdkresource.WithAttributes(
			attribute.String("service.name", cfg.OTELServiceName),
			attribute.String("deployment.environment", cfg.OTELEnvironment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create trace resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.OTELTraceSamplingRatio))),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	logger.Info("otel tracing initialized", "endpoint", cfg.OTELExporterOTLPEndpoint, "sampling_ratio", cfg.OTELTraceSamplingRatio)
	return tp, nil
}
