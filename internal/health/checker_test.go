package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockChecker struct {
	result CheckResult
}

func (m mockChecker) Check(context.Context) CheckResult {
	return m.result
}

func TestProbeRunnerReady(t *testing.T) {
	runner := NewProbeRunner(200*time.Millisecond, 0,
		mockChecker{result: CheckResult{Name: "db", Healthy: true}},
		mockChecker{result: CheckResult{Name: "redis", Healthy: true}},
	)
	ready, results := runner.Ready(context.Background())
	if !ready {
		t.Fatal("expected ready")
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestProbeRunnerUnready(t *testing.T) {
	runner := NewProbeRunner(200*time.Millisecond, 0,
		mockChecker{result: CheckResult{Name: "db", Healthy: true}},
		mockChecker{result: CheckResult{Name: "redis", Healthy: false, Error: errors.New("down").Error()}},
	)
	ready, results := runner.Ready(context.Background())
	if ready {
		t.Fatal("expected unready")
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestProbeRunnerStartupGrace(t *testing.T) {
	runner := NewProbeRunner(200*time.Millisecond, 2*time.Second,
		mockChecker{result: CheckResult{Name: "db", Healthy: true}},
	)
	ready, results := runner.Ready(context.Background())
	if ready {
		t.Fatal("expected unready during grace period")
	}
	if len(results) != 1 || results[0].Name != "startup_grace" {
		t.Fatalf("unexpected grace results: %+v", results)
	}
}
