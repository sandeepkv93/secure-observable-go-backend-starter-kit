package service

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
)

var redisAuthAbuseBumpScript = redis.NewScript(`
local now_ms = tonumber(ARGV[1])
local base_ms = tonumber(ARGV[2])
local multiplier = tonumber(ARGV[3])
local max_ms = tonumber(ARGV[4])
local reset_ms = tonumber(ARGV[5])
local free_attempts = tonumber(ARGV[6])

local key = KEYS[1]
local fail_count = tonumber(redis.call("HGET", key, "fail_count") or "0")
local last_failure_ms = tonumber(redis.call("HGET", key, "last_failure_ms") or "0")

if last_failure_ms == 0 or (now_ms - last_failure_ms) > reset_ms then
  fail_count = 0
end

fail_count = fail_count + 1
local delay = 0
if fail_count > free_attempts then
  delay = math.floor(base_ms * (multiplier ^ (fail_count - free_attempts - 1)))
end
if delay > max_ms then
  delay = max_ms
end
if delay > 0 and delay < 1 then
  delay = 1
end

local cooldown_until_ms = now_ms + delay
redis.call("HSET", key, "fail_count", tostring(fail_count), "last_failure_ms", tostring(now_ms), "cooldown_until_ms", tostring(cooldown_until_ms))
local ttl_ms = reset_ms + delay + 60000
redis.call("PEXPIRE", key, ttl_ms)
return delay
`)

type RedisAuthAbuseGuard struct {
	client redis.UniversalClient
	prefix string
	policy AuthAbusePolicy
}

func NewRedisAuthAbuseGuard(client redis.UniversalClient, prefix string, policy AuthAbusePolicy) *RedisAuthAbuseGuard {
	if prefix == "" {
		prefix = "auth_abuse"
	}
	return &RedisAuthAbuseGuard{
		client: client,
		prefix: prefix,
		policy: normalizeAuthAbusePolicy(policy),
	}
}

func (g *RedisAuthAbuseGuard) Check(ctx context.Context, scope AuthAbuseScope, identity, ip string) (time.Duration, error) {
	now := time.Now().UTC()
	identityDelay, err := g.cooldownForKey(ctx, g.stateKey(scope, "id", normalizeAuthIdentity(identity)), now)
	if err != nil {
		return 0, err
	}
	ipDelay, err := g.cooldownForKey(ctx, g.stateKey(scope, "ip", normalizeAuthIP(ip)), now)
	if err != nil {
		return 0, err
	}
	return max(identityDelay, ipDelay), nil
}

func (g *RedisAuthAbuseGuard) RegisterFailure(ctx context.Context, scope AuthAbuseScope, identity, ip string) (time.Duration, error) {
	nowMS := time.Now().UTC().UnixMilli()
	identityDelay, err := g.bumpKey(ctx, g.stateKey(scope, "id", normalizeAuthIdentity(identity)), nowMS)
	if err != nil {
		return 0, err
	}
	ipDelay, err := g.bumpKey(ctx, g.stateKey(scope, "ip", normalizeAuthIP(ip)), nowMS)
	if err != nil {
		return 0, err
	}
	return max(identityDelay, ipDelay), nil
}

func (g *RedisAuthAbuseGuard) Reset(ctx context.Context, scope AuthAbuseScope, identity, ip string) error {
	_, err := g.client.Del(
		ctx,
		g.stateKey(scope, "id", normalizeAuthIdentity(identity)),
		g.stateKey(scope, "ip", normalizeAuthIP(ip)),
	).Result()
	return err
}

func (g *RedisAuthAbuseGuard) bumpKey(ctx context.Context, key string, nowMS int64) (time.Duration, error) {
	result, err := redisAuthAbuseBumpScript.Run(
		ctx,
		g.client,
		[]string{key},
		nowMS,
		g.policy.BaseDelay.Milliseconds(),
		g.policy.Multiplier,
		g.policy.MaxDelay.Milliseconds(),
		g.policy.ResetWindow.Milliseconds(),
		g.policy.FreeAttempts,
	).Result()
	if err != nil {
		return 0, err
	}
	delayMS, err := parseAuthAbuseRedisInt64(result)
	if err != nil {
		return 0, err
	}
	return time.Duration(max(delayMS, int64(0))) * time.Millisecond, nil
}

func (g *RedisAuthAbuseGuard) cooldownForKey(ctx context.Context, key string, now time.Time) (time.Duration, error) {
	values, err := g.client.HMGet(ctx, key, "last_failure_ms", "cooldown_until_ms").Result()
	if err != nil {
		return 0, err
	}
	if len(values) != 2 || values[0] == nil || values[1] == nil {
		return 0, nil
	}
	lastFailureMS, err := parseAuthAbuseRedisInt64(values[0])
	if err != nil {
		return 0, err
	}
	cooldownUntilMS, err := parseAuthAbuseRedisInt64(values[1])
	if err != nil {
		return 0, err
	}
	nowMS := now.UnixMilli()
	if nowMS-lastFailureMS > g.policy.ResetWindow.Milliseconds() {
		return 0, nil
	}
	if cooldownUntilMS <= nowMS {
		return 0, nil
	}
	return time.Duration(cooldownUntilMS-nowMS) * time.Millisecond, nil
}

func (g *RedisAuthAbuseGuard) stateKey(scope AuthAbuseScope, dim, value string) string {
	return fmt.Sprintf("%s:%s:%s:%s", g.prefix, scope, dim, hashToken(value))
}

func parseAuthAbuseRedisInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case uint64:
		if n > math.MaxInt64 {
			return 0, fmt.Errorf("redis response overflows int64")
		}
		return int64(n), nil
	case int:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("unexpected redis response type %T", v)
	}
}
