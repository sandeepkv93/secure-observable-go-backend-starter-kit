package service

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryAuthAbuseGuardExponentialCooldown(t *testing.T) {
	guard := NewInMemoryAuthAbuseGuard(AuthAbusePolicy{
		FreeAttempts: 0,
		BaseDelay:    10 * time.Millisecond,
		Multiplier:   2,
		MaxDelay:     100 * time.Millisecond,
		ResetWindow:  time.Second,
	})
	ctx := context.Background()

	if retry, err := guard.Check(ctx, AuthAbuseScopeLogin, "a@example.com", "10.0.0.1"); err != nil || retry != 0 {
		t.Fatalf("expected no cooldown initially, got retry=%v err=%v", retry, err)
	}
	r1, err := guard.RegisterFailure(ctx, AuthAbuseScopeLogin, "a@example.com", "10.0.0.1")
	if err != nil {
		t.Fatalf("register failure #1: %v", err)
	}
	r2, err := guard.RegisterFailure(ctx, AuthAbuseScopeLogin, "a@example.com", "10.0.0.1")
	if err != nil {
		t.Fatalf("register failure #2: %v", err)
	}
	if r2 <= r1 {
		t.Fatalf("expected increasing cooldown, got r1=%v r2=%v", r1, r2)
	}
}

func TestInMemoryAuthAbuseGuardResetClearsCooldown(t *testing.T) {
	guard := NewInMemoryAuthAbuseGuard(AuthAbusePolicy{
		FreeAttempts: 0,
		BaseDelay:    time.Second,
		Multiplier:   2,
		MaxDelay:     10 * time.Second,
		ResetWindow:  time.Minute,
	})
	ctx := context.Background()
	_, _ = guard.RegisterFailure(ctx, AuthAbuseScopeLogin, "b@example.com", "10.0.0.2")
	if retry, _ := guard.Check(ctx, AuthAbuseScopeLogin, "b@example.com", "10.0.0.2"); retry <= 0 {
		t.Fatal("expected active cooldown before reset")
	}
	if err := guard.Reset(ctx, AuthAbuseScopeLogin, "b@example.com", "10.0.0.2"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if retry, _ := guard.Check(ctx, AuthAbuseScopeLogin, "b@example.com", "10.0.0.2"); retry != 0 {
		t.Fatalf("expected cooldown to be cleared, got %v", retry)
	}
}

func TestInMemoryAuthAbuseGuardDimensionIsolation(t *testing.T) {
	guard := NewInMemoryAuthAbuseGuard(AuthAbusePolicy{
		FreeAttempts: 0,
		BaseDelay:    time.Second,
		Multiplier:   2,
		MaxDelay:     10 * time.Second,
		ResetWindow:  time.Minute,
	})
	ctx := context.Background()
	_, _ = guard.RegisterFailure(ctx, AuthAbuseScopeLogin, "c@example.com", "10.0.0.3")

	if retry, _ := guard.Check(ctx, AuthAbuseScopeLogin, "c@example.com", "10.0.0.9"); retry <= 0 {
		t.Fatal("expected identity dimension to trigger cooldown")
	}
	if retry, _ := guard.Check(ctx, AuthAbuseScopeLogin, "z@example.com", "10.0.0.3"); retry <= 0 {
		t.Fatal("expected ip dimension to trigger cooldown")
	}
	if retry, _ := guard.Check(ctx, AuthAbuseScopeLogin, "z@example.com", "10.0.0.9"); retry != 0 {
		t.Fatalf("expected unrelated identity+ip to be unaffected, got %v", retry)
	}
}
