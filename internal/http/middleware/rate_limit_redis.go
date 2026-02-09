package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var redisFixedWindowScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("PTTL", KEYS[1])
return {current, ttl}
`)

type RedisFixedWindowLimiter struct {
	client redis.UniversalClient
	prefix string
}

func NewRedisFixedWindowLimiter(client redis.UniversalClient, prefix string) *RedisFixedWindowLimiter {
	if prefix == "" {
		prefix = "rl"
	}
	return &RedisFixedWindowLimiter{
		client: client,
		prefix: prefix,
	}
}

func (l *RedisFixedWindowLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	if l.client == nil {
		return false, window, fmt.Errorf("redis client is nil")
	}
	if key == "" {
		key = "unknown"
	}
	windowMS := int(window / time.Millisecond)
	if windowMS <= 0 {
		windowMS = 1000
	}
	storeKey := fmt.Sprintf("%s:%s", l.prefix, key)
	raw, err := redisFixedWindowScript.Run(ctx, l.client, []string{storeKey}, windowMS).Result()
	if err != nil {
		return false, window, err
	}
	values, ok := raw.([]interface{})
	if !ok || len(values) != 2 {
		return false, window, fmt.Errorf("unexpected redis script response type")
	}

	count, err := parseRedisInt64(values[0])
	if err != nil {
		return false, window, err
	}
	ttlMS, err := parseRedisInt64(values[1])
	if err != nil {
		return false, window, err
	}
	if ttlMS <= 0 {
		ttlMS = int64(window / time.Millisecond)
		if ttlMS <= 0 {
			ttlMS = 1000
		}
	}
	retryAfter := time.Duration(ttlMS) * time.Millisecond
	return count <= int64(limit), retryAfter, nil
}

func parseRedisInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case uint64:
		return int64(n), nil
	case int:
		return int64(n), nil
	case string:
		return 0, fmt.Errorf("unexpected string redis response: %s", n)
	default:
		return 0, fmt.Errorf("unexpected redis response type %T", v)
	}
}
