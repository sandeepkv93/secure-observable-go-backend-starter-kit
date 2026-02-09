package health

import (
	"context"
	"time"
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
		return false, []CheckResult{{Name: "startup_grace", Healthy: false, Error: "startup grace period active"}}
	}
	results := make([]CheckResult, 0, len(r.checkers))
	allHealthy := true
	for _, c := range r.checkers {
		checkCtx, cancel := context.WithTimeout(ctx, r.timeout)
		res := c.Check(checkCtx)
		cancel()
		results = append(results, res)
		if !res.Healthy {
			allHealthy = false
		}
	}
	return allHealthy, results
}
