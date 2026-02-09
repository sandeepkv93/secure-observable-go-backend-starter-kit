package integration

import (
	"context"
	"fmt"
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

func TestAdminListRolesSingleflightDedupesConcurrentMisses(t *testing.T) {
	cache := newTrackingAdminListCacheStore(service.NewInMemoryAdminListCacheStore())
	baseURL, adminClient, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "admin-cache-singleflight@example.com"
			cfg.AdminListCacheTTL = time.Minute
		},
		adminListCache: cache,
	})
	defer closeFn()

	registerAndLogin(t, adminClient, baseURL, "admin-cache-singleflight@example.com", "Valid#Pass1234")

	resp, env := doJSON(t, adminClient, http.MethodPost, baseURL+"/api/v1/admin/roles", map[string]any{
		"name":        "cache-sf-role",
		"description": "cached",
		"permissions": []string{"users:read"},
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("create role failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	const workers = 16
	url := baseURL + "/api/v1/admin/roles?name=cache-sf-role&sort_by=name&sort_order=asc&page=1&page_size=10"
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := doJSON(t, adminClient, http.MethodGet, url, nil, nil)
			if r.StatusCode != http.StatusOK || !e.Success {
				errCh <- fmt.Errorf("status=%d success=%v", r.StatusCode, e.Success)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent roles list failed: %v", err)
		}
	}

	_, setCalls, _ := cache.Snapshot()
	if setCalls != 1 {
		t.Fatalf("expected one cache set for concurrent miss burst, got %d", setCalls)
	}
}

func TestAdminListConditionalETagForRolesAndPermissions(t *testing.T) {
	baseURL, adminClient, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "admin-etag@example.com"
		},
	})
	defer closeFn()

	registerAndLogin(t, adminClient, baseURL, "admin-etag@example.com", "Valid#Pass1234")

	// Seed one role and one permission.
	resp, env := doJSON(t, adminClient, http.MethodPost, baseURL+"/api/v1/admin/roles", map[string]any{
		"name":        "etag-role-a",
		"description": "etag role",
		"permissions": []string{"users:read"},
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("create etag role failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	resp, env = doJSON(t, adminClient, http.MethodPost, baseURL+"/api/v1/admin/permissions", map[string]any{
		"resource": "etag_resource",
		"action":   "read_a",
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("create etag permission failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	rolesURL := baseURL + "/api/v1/admin/roles?name=etag-role-&sort_by=name&sort_order=asc&page=1&page_size=10"
	permsURL := baseURL + "/api/v1/admin/permissions?resource=etag_resource&sort_by=action&sort_order=asc&page=1&page_size=10"

	// Roles: first response should include ETag, second with If-None-Match should be 304.
	resp, env = doJSON(t, adminClient, http.MethodGet, rolesURL, nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("initial roles list failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	roleETag := resp.Header.Get("ETag")
	if roleETag == "" {
		t.Fatal("expected roles ETag header")
	}
	if got := resp.Header.Get("Cache-Control"); got != "private, no-cache" {
		t.Fatalf("unexpected roles cache-control: %q", got)
	}

	resp, _ = doJSON(t, adminClient, http.MethodGet, rolesURL, nil, map[string]string{
		"If-None-Match": roleETag,
	})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304 for roles If-None-Match, got %d", resp.StatusCode)
	}
	if resp.Header.Get("ETag") != roleETag {
		t.Fatalf("expected same roles ETag on 304 response")
	}

	// Mutate roles and ensure the old ETag no longer matches.
	resp, env = doJSON(t, adminClient, http.MethodPost, baseURL+"/api/v1/admin/roles", map[string]any{
		"name":        "etag-role-b",
		"description": "etag role",
		"permissions": []string{"users:read"},
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("create second etag role failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	resp, env = doJSON(t, adminClient, http.MethodGet, rolesURL, nil, map[string]string{
		"If-None-Match": roleETag,
	})
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("expected 200 roles after mutation with stale If-None-Match, got %d", resp.StatusCode)
	}
	if updated := resp.Header.Get("ETag"); updated == "" || updated == roleETag {
		t.Fatalf("expected changed roles ETag after mutation, old=%q new=%q", roleETag, updated)
	}

	// Permissions: first response should include ETag, second with If-None-Match should be 304.
	resp, env = doJSON(t, adminClient, http.MethodGet, permsURL, nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("initial permissions list failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	permETag := resp.Header.Get("ETag")
	if permETag == "" {
		t.Fatal("expected permissions ETag header")
	}
	if got := resp.Header.Get("Cache-Control"); got != "private, no-cache" {
		t.Fatalf("unexpected permissions cache-control: %q", got)
	}

	resp, _ = doJSON(t, adminClient, http.MethodGet, permsURL, nil, map[string]string{
		"If-None-Match": permETag,
	})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304 for permissions If-None-Match, got %d", resp.StatusCode)
	}
	if resp.Header.Get("ETag") != permETag {
		t.Fatalf("expected same permissions ETag on 304 response")
	}

	// Mutate permissions and ensure stale ETag yields fresh payload.
	resp, env = doJSON(t, adminClient, http.MethodPost, baseURL+"/api/v1/admin/permissions", map[string]any{
		"resource": "etag_resource",
		"action":   "read_b",
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("create second etag permission failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	resp, env = doJSON(t, adminClient, http.MethodGet, permsURL, nil, map[string]string{
		"If-None-Match": permETag,
	})
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("expected 200 permissions after mutation with stale If-None-Match, got %d", resp.StatusCode)
	}
	if updated := resp.Header.Get("ETag"); updated == "" || updated == permETag {
		t.Fatalf("expected changed permissions ETag after mutation, old=%q new=%q", permETag, updated)
	}
}
