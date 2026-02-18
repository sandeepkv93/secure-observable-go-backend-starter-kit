package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
)

func TestProbeRunnerReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	dbChecker := NewMockChecker(ctrl)
	redisChecker := NewMockChecker(ctrl)
	dbChecker.EXPECT().Check(gomock.Any()).Return(CheckResult{Name: "db", Healthy: true})
	redisChecker.EXPECT().Check(gomock.Any()).Return(CheckResult{Name: "redis", Healthy: true})

	runner := NewProbeRunner(200*time.Millisecond, 0,
		dbChecker,
		redisChecker,
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
	ctrl := gomock.NewController(t)
	dbChecker := NewMockChecker(ctrl)
	redisChecker := NewMockChecker(ctrl)
	dbChecker.EXPECT().Check(gomock.Any()).Return(CheckResult{Name: "db", Healthy: true})
	redisChecker.EXPECT().Check(gomock.Any()).Return(CheckResult{Name: "redis", Healthy: false, Error: errors.New("down").Error()})

	runner := NewProbeRunner(200*time.Millisecond, 0,
		dbChecker,
		redisChecker,
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
	ctrl := gomock.NewController(t)
	dbChecker := NewMockChecker(ctrl)
	dbChecker.EXPECT().Check(gomock.Any()).Times(0)

	runner := NewProbeRunner(200*time.Millisecond, 2*time.Second,
		dbChecker,
	)
	ready, results := runner.Ready(context.Background())
	if ready {
		t.Fatal("expected unready during grace period")
	}
	if len(results) != 1 || results[0].Name != "startup_grace" {
		t.Fatalf("unexpected grace results: %+v", results)
	}
}

func TestHealthOutcome(t *testing.T) {
	if got := healthOutcome(context.DeadlineExceeded, CheckResult{Name: "db", Healthy: false}); got != "timeout" {
		t.Fatalf("expected timeout outcome, got %q", got)
	}
	if got := healthOutcome(nil, CheckResult{Name: "db", Healthy: true}); got != "healthy" {
		t.Fatalf("expected healthy outcome, got %q", got)
	}
	if got := healthOutcome(nil, CheckResult{Name: "db", Healthy: false}); got != "unhealthy" {
		t.Fatalf("expected unhealthy outcome, got %q", got)
	}
}
