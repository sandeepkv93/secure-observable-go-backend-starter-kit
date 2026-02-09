package observability

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/attribute"
	otlploggrpc "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
)

type multiHandler struct {
	handlers []slog.Handler
}

type traceContextHandler struct {
	next slog.Handler
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		if err := handler.Handle(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		next = append(next, handler.WithAttrs(attrs))
	}
	return &multiHandler{handlers: next}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		next = append(next, handler.WithGroup(name))
	}
	return &multiHandler{handlers: next}
}

func (h *traceContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *traceContextHandler) Handle(ctx context.Context, r slog.Record) error {
	traceID := ""
	spanID := ""
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		traceID = sc.TraceID().String()
		spanID = sc.SpanID().String()
	}
	r.AddAttrs(
		slog.String("trace_id", traceID),
		slog.String("span_id", spanID),
	)
	return h.next.Handle(ctx, r)
}

func (h *traceContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceContextHandler{next: h.next.WithAttrs(attrs)}
}

func (h *traceContextHandler) WithGroup(name string) slog.Handler {
	return &traceContextHandler{next: h.next.WithGroup(name)}
}

var (
	loggerMu     sync.RWMutex
	globalLogger *slog.Logger
)

func NewLogger() *slog.Logger {
	loggerMu.RLock()
	l := globalLogger
	loggerMu.RUnlock()
	if l != nil {
		return l
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func NewBootstrapLogger(cfg *config.Config) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.OTELLogLevel)}))
}

func InitLogger(cfg *config.Config, lp *sdklog.LoggerProvider) *slog.Logger {
	level := parseLogLevel(cfg.OTELLogLevel)
	stdout := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	if !cfg.OTELLogsEnabled || lp == nil {
		l := slog.New(&traceContextHandler{next: stdout})
		loggerMu.Lock()
		globalLogger = l
		loggerMu.Unlock()
		slog.SetDefault(l)
		return l
	}

	otelHandler := otelslog.NewHandler(cfg.OTELServiceName, otelslog.WithLoggerProvider(lp))
	l := slog.New(&traceContextHandler{next: &multiHandler{handlers: []slog.Handler{stdout, otelHandler}}})
	loggerMu.Lock()
	globalLogger = l
	loggerMu.Unlock()
	slog.SetDefault(l)
	return l
}

func InitLogs(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*sdklog.LoggerProvider, error) {
	if !cfg.OTELLogsEnabled {
		logger.Info("otel logs disabled")
		return nil, nil
	}

	opts := []otlploggrpc.Option{otlploggrpc.WithEndpoint(cfg.OTELExporterOTLPEndpoint)}
	if cfg.OTELExporterOTLPInsecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	}
	exporter, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp log exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", cfg.OTELServiceName),
			attribute.String("deployment.environment", cfg.OTELEnvironment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create logs resource: %w", err)
	}

	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)
	logger.Info("otel logs initialized", "endpoint", cfg.OTELExporterOTLPEndpoint)
	return lp, nil
}

func parseLogLevel(v string) slog.Level {
	switch v {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
