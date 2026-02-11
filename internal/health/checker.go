package health

import (
	"context"
	"errors"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
)

type CheckResult struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
	Error   string `json:"error,omitempty"`
}

type Checker interface {
	Check(ctx context.Context) CheckResult
}

type ProbeRunner struct {
	checkers    []Checker
	timeout     time.Duration
	gracePeriod time.Duration
	startedAt   time.Time
}

func NewProbeRunner(timeout, gracePeriod time.Duration, checkers ...Checker) *ProbeRunner {
	if timeout <= 0 {
		timeout = time.Second
	}
	return &ProbeRunner{
		checkers:    checkers,
		timeout:     timeout,
		gracePeriod: gracePeriod,
		startedAt:   time.Now(),
	}
}

func (r *ProbeRunner) Ready(ctx context.Context) (bool, []CheckResult) {
	if r == nil {
		return true, nil
	}
	if r.gracePeriod > 0 && time.Since(r.startedAt) < r.gracePeriod {
		observability.RecordHealthCheckResult(ctx, "startup_grace", "unhealthy")
		observability.RecordHealthCheckDuration(ctx, "startup_grace", 0)
		return false, []CheckResult{{Name: "startup_grace", Healthy: false, Error: "startup grace period active"}}
	}
	results := make([]CheckResult, 0, len(r.checkers))
	allHealthy := true
	for _, c := range r.checkers {
		checkCtx, cancel := context.WithTimeout(ctx, r.timeout)
		start := time.Now()
		res := c.Check(checkCtx)
		duration := time.Since(start)
		outcome := healthOutcome(checkCtx.Err(), res)
		observability.RecordHealthCheckResult(ctx, res.Name, outcome)
		observability.RecordHealthCheckDuration(ctx, res.Name, duration)
		cancel()
		results = append(results, res)
		if !res.Healthy {
			allHealthy = false
		}
	}
	return allHealthy, results
}

func healthOutcome(ctxErr error, res CheckResult) string {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return "timeout"
	}
	if res.Healthy {
		return "healthy"
	}
	return "unhealthy"
}
