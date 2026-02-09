package integration

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

type trackingAdminListCacheStore struct {
	delegate service.AdminListCacheStore

	mu              sync.Mutex
	getCalls        int
	setCalls        int
	invalidateCalls int
}

func newTrackingAdminListCacheStore(delegate service.AdminListCacheStore) *trackingAdminListCacheStore {
	return &trackingAdminListCacheStore{delegate: delegate}
}

func (s *trackingAdminListCacheStore) Get(ctx context.Context, namespace, key string) ([]byte, bool, error) {
	s.mu.Lock()
	s.getCalls++
	s.mu.Unlock()
	return s.delegate.Get(ctx, namespace, key)
}

func (s *trackingAdminListCacheStore) Set(ctx context.Context, namespace, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	s.setCalls++
	s.mu.Unlock()
	return s.delegate.Set(ctx, namespace, key, value, ttl)
}

func (s *trackingAdminListCacheStore) InvalidateNamespace(ctx context.Context, namespace string) error {
	s.mu.Lock()
	s.invalidateCalls++
	s.mu.Unlock()
	return s.delegate.InvalidateNamespace(ctx, namespace)
}

func (s *trackingAdminListCacheStore) Snapshot() (getCalls, setCalls, invalidateCalls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getCalls, s.setCalls, s.invalidateCalls
}

func TestAdminListRolesReadThroughCacheAndInvalidation(t *testing.T) {
	cache := newTrackingAdminListCacheStore(service.NewInMemoryAdminListCacheStore())
	baseURL, adminClient, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "admin-cache@example.com"
			cfg.AdminListCacheTTL = time.Minute
		},
		adminListCache: cache,
	})
	defer closeFn()

	registerAndLogin(t, adminClient, baseURL, "admin-cache@example.com", "Valid#Pass1234")

	resp, env := doJSON(t, adminClient, http.MethodPost, baseURL+"/api/v1/admin/roles", map[string]any{
		"name":        "cache-role-a",
		"description": "cached",
		"permissions": []string{"users:read"},
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("create initial role failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	// First read: miss + set.
	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/roles?name=cache-role-&sort_by=name&sort_order=asc&page=1&page_size=10", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("first roles list failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	_, setCalls1, _ := cache.Snapshot()
	if setCalls1 != 1 {
		t.Fatalf("expected one cache set after first read, got %d", setCalls1)
	}

	// Second read with same query should hit cache (no additional set).
	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/roles?name=cache-role-&sort_by=name&sort_order=asc&page=1&page_size=10", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("second roles list failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	_, setCalls2, _ := cache.Snapshot()
	if setCalls2 != setCalls1 {
		t.Fatalf("expected cache hit with no new set, before=%d after=%d", setCalls1, setCalls2)
	}

	// Mutation should invalidate cached role lists.
	resp, env = doJSON(t, adminClient, http.MethodPost, baseURL+"/api/v1/admin/roles", map[string]any{
		"name":        "cache-role-b",
		"description": "cached",
		"permissions": []string{"users:read"},
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("create second role failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	_, _, invalidateCalls := cache.Snapshot()
	if invalidateCalls == 0 {
		t.Fatal("expected cache invalidation after role mutation")
	}

	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/roles?name=cache-role-&sort_by=name&sort_order=asc&page=1&page_size=10", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("post-invalidation roles list failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	_, setCalls3, _ := cache.Snapshot()
	if setCalls3 <= setCalls2 {
		t.Fatalf("expected cache repopulation after invalidation, before=%d after=%d", setCalls2, setCalls3)
	}
}
