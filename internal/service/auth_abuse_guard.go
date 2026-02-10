package service

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

type AuthAbuseScope string

const (
	AuthAbuseScopeLogin  AuthAbuseScope = "login"
	AuthAbuseScopeForgot AuthAbuseScope = "forgot"
)

type AuthAbusePolicy struct {
	FreeAttempts int
	BaseDelay    time.Duration
	Multiplier   float64
	MaxDelay     time.Duration
	ResetWindow  time.Duration
}

type AuthAbuseGuard interface {
	Check(ctx context.Context, scope AuthAbuseScope, identity, ip string) (time.Duration, error)
	RegisterFailure(ctx context.Context, scope AuthAbuseScope, identity, ip string) (time.Duration, error)
	Reset(ctx context.Context, scope AuthAbuseScope, identity, ip string) error
}

type NoopAuthAbuseGuard struct{}

func NewNoopAuthAbuseGuard() *NoopAuthAbuseGuard {
	return &NoopAuthAbuseGuard{}
}

func (g *NoopAuthAbuseGuard) Check(context.Context, AuthAbuseScope, string, string) (time.Duration, error) {
	return 0, nil
}

func (g *NoopAuthAbuseGuard) RegisterFailure(context.Context, AuthAbuseScope, string, string) (time.Duration, error) {
	return 0, nil
}

func (g *NoopAuthAbuseGuard) Reset(context.Context, AuthAbuseScope, string, string) error {
	return nil
}

type authAbuseEntry struct {
	FailCount     int
	LastFailureAt time.Time
	CooldownUntil time.Time
}

type InMemoryAuthAbuseGuard struct {
	mu     sync.Mutex
	policy AuthAbusePolicy
	data   map[string]authAbuseEntry
}

func NewInMemoryAuthAbuseGuard(policy AuthAbusePolicy) *InMemoryAuthAbuseGuard {
	return &InMemoryAuthAbuseGuard{
		policy: normalizeAuthAbusePolicy(policy),
		data:   make(map[string]authAbuseEntry),
	}
}

func (g *InMemoryAuthAbuseGuard) Check(_ context.Context, scope AuthAbuseScope, identity, ip string) (time.Duration, error) {
	now := time.Now().UTC()
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.maxActiveCooldownLocked(now, scope, identity, ip), nil
}

func (g *InMemoryAuthAbuseGuard) RegisterFailure(_ context.Context, scope AuthAbuseScope, identity, ip string) (time.Duration, error) {
	now := time.Now().UTC()
	g.mu.Lock()
	defer g.mu.Unlock()

	identityDelay := g.bumpLocked(now, g.stateKey(scope, "id", normalizeAuthIdentity(identity)))
	ipDelay := g.bumpLocked(now, g.stateKey(scope, "ip", normalizeAuthIP(ip)))
	return max(identityDelay, ipDelay), nil
}

func (g *InMemoryAuthAbuseGuard) Reset(_ context.Context, scope AuthAbuseScope, identity, ip string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	delete(g.data, g.stateKey(scope, "id", normalizeAuthIdentity(identity)))
	delete(g.data, g.stateKey(scope, "ip", normalizeAuthIP(ip)))
	return nil
}

func (g *InMemoryAuthAbuseGuard) bumpLocked(now time.Time, key string) time.Duration {
	entry := g.data[key]
	if entry.LastFailureAt.IsZero() || now.Sub(entry.LastFailureAt) > g.policy.ResetWindow {
		entry.FailCount = 0
	}
	entry.FailCount++
	entry.LastFailureAt = now
	delay := g.computeDelay(entry.FailCount)
	entry.CooldownUntil = now.Add(delay)
	g.data[key] = entry
	return delay
}

func (g *InMemoryAuthAbuseGuard) maxActiveCooldownLocked(now time.Time, scope AuthAbuseScope, identity, ip string) time.Duration {
	identityDelay := g.activeCooldownLocked(now, g.stateKey(scope, "id", normalizeAuthIdentity(identity)))
	ipDelay := g.activeCooldownLocked(now, g.stateKey(scope, "ip", normalizeAuthIP(ip)))
	return max(identityDelay, ipDelay)
}

func (g *InMemoryAuthAbuseGuard) activeCooldownLocked(now time.Time, key string) time.Duration {
	entry, ok := g.data[key]
	if !ok {
		return 0
	}
	if now.Sub(entry.LastFailureAt) > g.policy.ResetWindow {
		delete(g.data, key)
		return 0
	}
	if now.After(entry.CooldownUntil) {
		return 0
	}
	return entry.CooldownUntil.Sub(now)
}

func (g *InMemoryAuthAbuseGuard) computeDelay(failCount int) time.Duration {
	if failCount <= 0 {
		return 0
	}
	if failCount <= g.policy.FreeAttempts {
		return 0
	}
	power := math.Pow(g.policy.Multiplier, float64(failCount-g.policy.FreeAttempts-1))
	delay := time.Duration(float64(g.policy.BaseDelay) * power)
	if delay > g.policy.MaxDelay {
		return g.policy.MaxDelay
	}
	return delay
}

func (g *InMemoryAuthAbuseGuard) stateKey(scope AuthAbuseScope, dim, value string) string {
	return fmt.Sprintf("%s:%s:%s", scope, dim, value)
}

func normalizeAuthIdentity(identity string) string {
	v := strings.TrimSpace(strings.ToLower(identity))
	if v == "" {
		return "anonymous"
	}
	return v
}

func normalizeAuthIP(ip string) string {
	v := strings.TrimSpace(strings.ToLower(ip))
	if v == "" {
		return "unknown"
	}
	return v
}

func normalizeAuthAbusePolicy(policy AuthAbusePolicy) AuthAbusePolicy {
	if policy.FreeAttempts < 0 {
		policy.FreeAttempts = 0
	}
	if policy.BaseDelay <= 0 {
		policy.BaseDelay = 2 * time.Second
	}
	if policy.Multiplier < 1 {
		policy.Multiplier = 2
	}
	if policy.MaxDelay < policy.BaseDelay {
		policy.MaxDelay = 5 * time.Minute
	}
	if policy.ResetWindow <= 0 {
		policy.ResetWindow = 30 * time.Minute
	}
	return policy
}
