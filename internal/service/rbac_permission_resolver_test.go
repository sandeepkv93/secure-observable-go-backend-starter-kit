package service

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
)

type stubUserService struct {
	perms []string
	delay time.Duration
	mu    sync.Mutex
	calls int
}

func (s *stubUserService) GetByID(id uint) (*domain.User, []string, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return &domain.User{ID: id}, append([]string(nil), s.perms...), nil
}

func (s *stubUserService) List() ([]domain.User, error) {
	return nil, nil
}

func (s *stubUserService) SetRoles(uint, []uint) error {
	return nil
}

func (s *stubUserService) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestCachedPermissionResolverCachesBySession(t *testing.T) {
	store := NewInMemoryRBACPermissionCacheStore()
	userSvc := &stubUserService{perms: []string{"users:read"}}
	resolver := NewCachedPermissionResolver(store, userSvc, time.Minute)

	claims := &security.Claims{}
	claims.Subject = "42"
	claims.ID = "jti-1"

	perms, err := resolver.ResolvePermissions(context.Background(), claims)
	if err != nil {
		t.Fatalf("resolve permissions first call: %v", err)
	}
	if len(perms) != 1 || perms[0] != "users:read" {
		t.Fatalf("unexpected perms: %+v", perms)
	}
	if userSvc.Calls() != 1 {
		t.Fatalf("expected one user service call, got %d", userSvc.Calls())
	}

	perms, err = resolver.ResolvePermissions(context.Background(), claims)
	if err != nil {
		t.Fatalf("resolve permissions second call: %v", err)
	}
	if len(perms) != 1 || perms[0] != "users:read" {
		t.Fatalf("unexpected perms second call: %+v", perms)
	}
	if userSvc.Calls() != 1 {
		t.Fatalf("expected cache hit and unchanged user service calls, got %d", userSvc.Calls())
	}
}

func TestCachedPermissionResolverInvalidateUser(t *testing.T) {
	store := NewInMemoryRBACPermissionCacheStore()
	userSvc := &stubUserService{perms: []string{"roles:read"}}
	resolver := NewCachedPermissionResolver(store, userSvc, time.Minute)

	claims := &security.Claims{}
	claims.Subject = "7"
	claims.ID = "jti-x"

	if _, err := resolver.ResolvePermissions(context.Background(), claims); err != nil {
		t.Fatalf("resolve permissions: %v", err)
	}
	if err := resolver.InvalidateUser(context.Background(), 7); err != nil {
		t.Fatalf("invalidate user: %v", err)
	}
	if _, err := resolver.ResolvePermissions(context.Background(), claims); err != nil {
		t.Fatalf("resolve permissions after invalidate: %v", err)
	}
	if userSvc.Calls() != 2 {
		t.Fatalf("expected cache miss after invalidate, got user service calls=%d", userSvc.Calls())
	}
}

func TestCachedPermissionResolverSingleflightDedupesConcurrentMisses(t *testing.T) {
	store := NewInMemoryRBACPermissionCacheStore()
	userSvc := &stubUserService{
		perms: []string{"roles:read", "roles:write"},
		delay: 40 * time.Millisecond,
	}
	resolver := NewCachedPermissionResolver(store, userSvc, time.Minute)

	claims := &security.Claims{}
	claims.Subject = "55"
	claims.ID = "jti-concurrent"

	const workers = 20
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			perms, err := resolver.ResolvePermissions(context.Background(), claims)
			if err != nil {
				errCh <- err
				return
			}
			if len(perms) != 2 {
				errCh <- fmt.Errorf("unexpected perms size: %d", len(perms))
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("resolve failed: %v", err)
		}
	}
	if userSvc.Calls() != 1 {
		t.Fatalf("expected singleflight dedupe to one GetByID call, got %d", userSvc.Calls())
	}
}
