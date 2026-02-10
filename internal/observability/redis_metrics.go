package observability

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var redisInstrumentationOnce sync.Once

// InstrumentRedisClient wires redis command and pool observability into the provided client.
// It is safe to call multiple times; instrumentation is installed once per process.
func InstrumentRedisClient(client redis.UniversalClient, logger *slog.Logger) {
	if client == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}

	redisInstrumentationOnce.Do(func() {
		hook, err := newRedisMetricsHook(client)
		if err != nil {
			logger.Warn("redis observability instrumentation disabled", "error", err)
			return
		}
		client.AddHook(hook)
		logger.Info("redis observability instrumentation enabled")
	})
}

type redisMetricsHook struct {
	cmdTotal       metric.Int64Counter
	cmdErrors      metric.Int64Counter
	cmdLatency     metric.Float64Histogram
	keyspaceHits   metric.Int64Counter
	keyspaceMisses metric.Int64Counter

	cmdTotalAtomic  atomic.Int64
	cmdErrorAtomic  atomic.Int64
	keyHitAtomic    atomic.Int64
	keyMissAtomic   atomic.Int64
	poolStatsReader func() *redis.PoolStats
}

func newRedisMetricsHook(client redis.UniversalClient) (*redisMetricsHook, error) {
	meter := otel.Meter("secure-observable-go-backend-starter-kit")

	cmdTotal, err := meter.Int64Counter(
		"redis.command.total",
		metric.WithDescription("Total number of Redis commands executed"),
	)
	if err != nil {
		return nil, err
	}
	cmdErrors, err := meter.Int64Counter(
		"redis.command.errors",
		metric.WithDescription("Total number of Redis command errors"),
	)
	if err != nil {
		return nil, err
	}
	cmdLatency, err := meter.Float64Histogram(
		"redis.command.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Redis command latency in seconds"),
	)
	if err != nil {
		return nil, err
	}
	keyHits, err := meter.Int64Counter(
		"redis.keyspace.hits",
		metric.WithDescription("Redis keyspace hits observed by client operations"),
	)
	if err != nil {
		return nil, err
	}
	keyMisses, err := meter.Int64Counter(
		"redis.keyspace.misses",
		metric.WithDescription("Redis keyspace misses observed by client operations"),
	)
	if err != nil {
		return nil, err
	}

	poolSaturationGauge, err := meter.Float64ObservableGauge(
		"redis.pool.saturation",
		metric.WithUnit("1"),
		metric.WithDescription("Redis pool saturation ratio (used_conns / total_conns)"),
	)
	if err != nil {
		return nil, err
	}
	keyspaceHitRatioGauge, err := meter.Float64ObservableGauge(
		"redis.keyspace.hit_ratio",
		metric.WithUnit("1"),
		metric.WithDescription("Redis keyspace hit ratio (hits / (hits + misses)) from client-observed operations"),
	)
	if err != nil {
		return nil, err
	}
	commandErrorRateGauge, err := meter.Float64ObservableGauge(
		"redis.command.error_rate",
		metric.WithUnit("1"),
		metric.WithDescription("Redis command error rate (errors / total commands)"),
	)
	if err != nil {
		return nil, err
	}

	hook := &redisMetricsHook{
		cmdTotal:       cmdTotal,
		cmdErrors:      cmdErrors,
		cmdLatency:     cmdLatency,
		keyspaceHits:   keyHits,
		keyspaceMisses: keyMisses,
		poolStatsReader: func() *redis.PoolStats {
			return client.PoolStats()
		},
	}

	_, err = meter.RegisterCallback(func(ctx context.Context, observer metric.Observer) error {
		stats := hook.poolStatsReader()
		if stats != nil && stats.TotalConns > 0 {
			used := stats.TotalConns - stats.IdleConns
			saturation := clampRatio(float64(used) / float64(stats.TotalConns))
			observer.ObserveFloat64(poolSaturationGauge, saturation)
		}

		hits := hook.keyHitAtomic.Load()
		misses := hook.keyMissAtomic.Load()
		if hits+misses > 0 {
			hitRatio := clampRatio(float64(hits) / float64(hits+misses))
			observer.ObserveFloat64(keyspaceHitRatioGauge, hitRatio)
		}

		total := hook.cmdTotalAtomic.Load()
		errors := hook.cmdErrorAtomic.Load()
		if total > 0 {
			errorRate := clampRatio(float64(errors) / float64(total))
			observer.ObserveFloat64(commandErrorRateGauge, errorRate)
		}
		return nil
	}, poolSaturationGauge, keyspaceHitRatioGauge, commandErrorRateGauge)
	if err != nil {
		return nil, err
	}

	return hook, nil
}

func (h *redisMetricsHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h *redisMetricsHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		start := time.Now()
		err := next(ctx, cmd)
		duration := time.Since(start)

		command := strings.ToLower(cmd.Name())
		status := redisCommandStatus(err)

		h.cmdTotalAtomic.Add(1)
		h.cmdTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("command", command),
			attribute.String("status", status),
		))

		if err != nil && err != redis.Nil {
			h.cmdErrorAtomic.Add(1)
			h.cmdErrors.Add(ctx, 1, metric.WithAttributes(
				attribute.String("command", command),
				attribute.String("error_type", classifyRedisError(err)),
			))
		}

		h.cmdLatency.Record(ctx, duration.Seconds(), metric.WithAttributes(
			attribute.String("command", command),
			attribute.String("status", status),
		))

		hits, misses, ok := classifyKeyspaceOutcome(cmd)
		if ok {
			if hits > 0 {
				h.keyHitAtomic.Add(hits)
				h.keyspaceHits.Add(ctx, hits)
			}
			if misses > 0 {
				h.keyMissAtomic.Add(misses)
				h.keyspaceMisses.Add(ctx, misses)
			}
		}

		return err
	}
}

func (h *redisMetricsHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		start := time.Now()
		err := next(ctx, cmds)
		duration := time.Since(start)

		pipelineStatus := redisCommandStatus(err)
		h.cmdLatency.Record(ctx, duration.Seconds(), metric.WithAttributes(
			attribute.String("command", "pipeline"),
			attribute.String("status", pipelineStatus),
		))

		for _, cmd := range cmds {
			command := strings.ToLower(cmd.Name())
			cmdErr := cmd.Err()
			status := redisCommandStatus(cmdErr)

			h.cmdTotalAtomic.Add(1)
			h.cmdTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("command", command),
				attribute.String("status", status),
			))

			if cmdErr != nil && cmdErr != redis.Nil {
				h.cmdErrorAtomic.Add(1)
				h.cmdErrors.Add(ctx, 1, metric.WithAttributes(
					attribute.String("command", command),
					attribute.String("error_type", classifyRedisError(cmdErr)),
				))
			}

			hits, misses, ok := classifyKeyspaceOutcome(cmd)
			if ok {
				if hits > 0 {
					h.keyHitAtomic.Add(hits)
					h.keyspaceHits.Add(ctx, hits)
				}
				if misses > 0 {
					h.keyMissAtomic.Add(misses)
					h.keyspaceMisses.Add(ctx, misses)
				}
			}
		}

		return err
	}
}

func redisCommandStatus(err error) string {
	switch err {
	case nil:
		return "success"
	case redis.Nil:
		return "miss"
	default:
		return "error"
	}
}

func classifyRedisError(err error) string {
	errStr := strings.ToLower(err.Error())
	switch {
	case strings.Contains(errStr, "timeout"):
		return "timeout"
	case strings.Contains(errStr, "connection"):
		return "connection"
	default:
		return "other"
	}
}

func classifyKeyspaceOutcome(cmd redis.Cmder) (hits int64, misses int64, ok bool) {
	name := strings.ToLower(cmd.Name())
	switch name {
	case "get", "hget", "lindex", "zscore":
		err := cmd.Err()
		if err == redis.Nil {
			return 0, 1, true
		}
		if err != nil {
			return 0, 0, false
		}
		return 1, 0, true
	case "exists":
		intCmd, castOK := cmd.(*redis.IntCmd)
		if !castOK {
			return 0, 0, false
		}
		v, err := intCmd.Result()
		if err != nil {
			return 0, 0, false
		}
		if v > 0 {
			return 1, 0, true
		}
		return 0, 1, true
	case "mget", "hmget":
		sliceCmd, castOK := cmd.(*redis.SliceCmd)
		if !castOK {
			return 0, 0, false
		}
		vals, err := sliceCmd.Result()
		if err != nil {
			return 0, 0, false
		}
		for _, v := range vals {
			if v == nil {
				misses++
			} else {
				hits++
			}
		}
		return hits, misses, true
	default:
		return 0, 0, false
	}
}

func clampRatio(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
