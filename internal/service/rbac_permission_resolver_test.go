package service

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"go.uber.org/mock/gomock"
)

func TestCachedPermissionResolverCachesBySession(t *testing.T) {
	store := NewInMemoryRBACPermissionCacheStore()
	ctrl := gomock.NewController(t)
	userSvc := NewMockUserServiceInterface(ctrl)
	userSvc.EXPECT().GetByID(uint(42)).Return(&domain.User{ID: 42}, []string{"users:read"}, nil).Times(1)

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

	perms, err = resolver.ResolvePermissions(context.Background(), claims)
	if err != nil {
		t.Fatalf("resolve permissions second call: %v", err)
	}
	if len(perms) != 1 || perms[0] != "users:read" {
		t.Fatalf("unexpected perms second call: %+v", perms)
	}
}

func TestCachedPermissionResolverInvalidateUser(t *testing.T) {
	store := NewInMemoryRBACPermissionCacheStore()
	ctrl := gomock.NewController(t)
	userSvc := NewMockUserServiceInterface(ctrl)
	userSvc.EXPECT().GetByID(uint(7)).Return(&domain.User{ID: 7}, []string{"roles:read"}, nil).Times(2)
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
}

func TestCachedPermissionResolverSingleflightDedupesConcurrentMisses(t *testing.T) {
	store := NewInMemoryRBACPermissionCacheStore()
	ctrl := gomock.NewController(t)
	userSvc := NewMockUserServiceInterface(ctrl)

	var (
		calls int
		mu    sync.Mutex
	)
	userSvc.EXPECT().GetByID(uint(55)).DoAndReturn(func(uint) (*domain.User, []string, error) {
		time.Sleep(40 * time.Millisecond)
		mu.Lock()
		calls++
		mu.Unlock()
		return &domain.User{ID: 55}, []string{"roles:read", "roles:write"}, nil
	}).Times(1)

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

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected singleflight dedupe to one GetByID call, got %d", calls)
	}
}
