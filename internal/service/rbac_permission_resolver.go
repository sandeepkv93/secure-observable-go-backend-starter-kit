package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
	"golang.org/x/sync/singleflight"
)

type CachedPermissionResolver struct {
	cacheStore RBACPermissionCacheStore
	userSvc    UserServiceInterface
	ttl        time.Duration
	sf         singleflight.Group
}

func NewCachedPermissionResolver(cacheStore RBACPermissionCacheStore, userSvc UserServiceInterface, ttl time.Duration) *CachedPermissionResolver {
	return &CachedPermissionResolver{
		cacheStore: cacheStore,
		userSvc:    userSvc,
		ttl:        ttl,
	}
}

func (r *CachedPermissionResolver) ResolvePermissions(ctx context.Context, claims *security.Claims) ([]string, error) {
	if claims == nil {
		return nil, fmt.Errorf("missing claims")
	}
	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid subject")
	}
	sessionTokenID := strings.TrimSpace(claims.ID)
	if sessionTokenID == "" {
		sessionTokenID = "none"
	}
	if r.cacheStore != nil && r.ttl > 0 {
		cached, ok, err := r.cacheStore.Get(ctx, uint(userID), sessionTokenID)
		if err == nil && ok {
			return cached, nil
		}
	}

	sfKey := fmt.Sprintf("rbacperm:user:%d:session:%s", userID, sessionTokenID)
	result, err, shared := r.sf.Do(sfKey, func() (interface{}, error) {
		if r.cacheStore != nil && r.ttl > 0 {
			cached, ok, err := r.cacheStore.Get(ctx, uint(userID), sessionTokenID)
			if err == nil && ok {
				return cached, nil
			}
		}
		_, perms, err := r.userSvc.GetByID(uint(userID))
		if err != nil {
			return nil, err
		}
		if r.cacheStore != nil && r.ttl > 0 {
			_ = r.cacheStore.Set(ctx, uint(userID), sessionTokenID, perms, r.ttl)
		}
		return perms, nil
	})
	if shared {
		observability.RecordRBACPermissionCacheEvent(ctx, "singleflight_shared")
	} else {
		observability.RecordRBACPermissionCacheEvent(ctx, "singleflight_leader")
	}
	if err != nil {
		return nil, err
	}
	perms, ok := result.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid permission result type")
	}
	return perms, nil
}

func (r *CachedPermissionResolver) InvalidateUser(ctx context.Context, userID uint) error {
	if r.cacheStore == nil {
		return nil
	}
	return r.cacheStore.InvalidateUser(ctx, userID)
}

func (r *CachedPermissionResolver) InvalidateAll(ctx context.Context) error {
	if r.cacheStore == nil {
		return nil
	}
	return r.cacheStore.InvalidateAll(ctx)
}

func buildRBACPermissionCacheKey(globalEpoch, userEpoch uint64, userID uint, sessionTokenID string) string {
	if sessionTokenID == "" {
		sessionTokenID = "none"
	}
	return fmt.Sprintf("rbacperm:g%d:u%d:user:%d:s:%s", globalEpoch, userEpoch, userID, sessionTokenID)
}
