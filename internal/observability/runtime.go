package observability

import (
	"context"
	"errors"
	"log/slog"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type Runtime struct {
	LoggerProvider *sdklog.LoggerProvider
	MeterProvider  *sdkmetric.MeterProvider
	TracerProvider *sdktrace.TracerProvider
}

func InitRuntime(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Runtime, error) {
	lp, err := InitLogs(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	mp, err := InitMetrics(ctx, cfg, logger)
	if err != nil {
		if lp != nil {
			_ = lp.Shutdown(ctx)
		}
		return nil, err
	}
	tp, err := InitTracing(ctx, cfg, logger)
	if err != nil {
		if mp != nil {
			_ = mp.Shutdown(ctx)
		}
		if lp != nil {
			_ = lp.Shutdown(ctx)
		}
		return nil, err
	}
	return &Runtime{LoggerProvider: lp, MeterProvider: mp, TracerProvider: tp}, nil
}

func (r *Runtime) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var errs []error
	if r.LoggerProvider != nil {
		if err := r.LoggerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if r.MeterProvider != nil {
		if err := r.MeterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if r.TracerProvider != nil {
		if err := r.TracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
