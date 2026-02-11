package middleware

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newRedisLimiterForTest(t *testing.T) (*miniredis.Miniredis, *redis.Client, *RedisFixedWindowLimiter) {
	t.Helper()
	m := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
		m.Close()
	})
	return m, client, NewRedisFixedWindowLimiter(client, "rl_test")
}

func TestRedisFixedWindowLimiterAllowDenyAndFallbackKey(t *testing.T) {
	_, _, limiter := newRedisLimiterForTest(t)
	ctx := context.Background()
	policy := RateLimitPolicy{SustainedLimit: 1, SustainedWindow: time.Second, BurstCapacity: 1, BurstRefillPerSec: 1}

	d1, err := limiter.Allow(ctx, "", policy)
	if err != nil {
		t.Fatalf("allow first request: %v", err)
	}
	if !d1.Allowed {
		t.Fatalf("expected first request to be allowed: %+v", d1)
	}

	d2, err := limiter.Allow(ctx, "", policy)
	if err != nil {
		t.Fatalf("allow second request: %v", err)
	}
	if d2.Allowed {
		t.Fatalf("expected second request denied: %+v", d2)
	}
	if d2.RetryAfter <= 0 {
		t.Fatalf("expected positive retry-after, got %v", d2.RetryAfter)
	}
}

func TestRedisFixedWindowLimiterBackendAndNilClientErrors(t *testing.T) {
	limiter := NewRedisFixedWindowLimiter(nil, "")
	if _, err := limiter.Allow(context.Background(), "k", RateLimitPolicy{}); err == nil {
		t.Fatal("expected nil client error")
	}

	badClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 20 * time.Millisecond, ReadTimeout: 20 * time.Millisecond, WriteTimeout: 20 * time.Millisecond})
	t.Cleanup(func() { _ = badClient.Close() })
	limiter = NewRedisFixedWindowLimiter(badClient, "")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := limiter.Allow(ctx, "k", RateLimitPolicy{}); err == nil {
		t.Fatal("expected backend error")
	}
}

func TestParseRedisInt64Branches(t *testing.T) {
	if v, err := parseRedisInt64(int64(4)); err != nil || v != 4 {
		t.Fatalf("int64 parse mismatch v=%d err=%v", v, err)
	}
	if v, err := parseRedisInt64(int(3)); err != nil || v != 3 {
		t.Fatalf("int parse mismatch v=%d err=%v", v, err)
	}
	if _, err := parseRedisInt64(uint64(math.MaxUint64)); err == nil {
		t.Fatal("expected overflow error for uint64")
	}
	if _, err := parseRedisInt64("1"); err == nil {
		t.Fatal("expected string type error")
	}
	if _, err := parseRedisInt64(errors.New("x")); err == nil {
		t.Fatal("expected unexpected type error")
	}
}
