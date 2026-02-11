package service

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryAdminListCacheStoreGetSetInvalidate(t *testing.T) {
	store := NewInMemoryAdminListCacheStore()
	ctx := context.Background()

	if err := store.Set(ctx, "admin.users", "k1", []byte(`{"x":1}`), time.Minute); err != nil {
		t.Fatalf("set cache: %v", err)
	}
	got, ok, err := store.Get(ctx, "admin.users", "k1")
	if err != nil {
		t.Fatalf("get cache: %v", err)
	}
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got) != `{"x":1}` {
		t.Fatalf("unexpected cache payload: %s", string(got))
	}
	withAge := any(store).(AdminListCacheStoreWithAge)
	_, ok, age, err := withAge.GetWithAge(ctx, "admin.users", "k1")
	if err != nil {
		t.Fatalf("get cache with age: %v", err)
	}
	if !ok {
		t.Fatal("expected cache hit from GetWithAge")
	}
	if age < 0 {
		t.Fatalf("expected non-negative age, got %v", age)
	}

	if err := store.InvalidateNamespace(ctx, "admin.users"); err != nil {
		t.Fatalf("invalidate namespace: %v", err)
	}
	_, ok, err = store.Get(ctx, "admin.users", "k1")
	if err != nil {
		t.Fatalf("get cache after invalidate: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss after invalidation")
	}
}

func TestInMemoryAdminListCacheStoreExpiry(t *testing.T) {
	store := NewInMemoryAdminListCacheStore()
	ctx := context.Background()

	if err := store.Set(ctx, "admin.roles", "k-expiry", []byte(`{"ok":true}`), 25*time.Millisecond); err != nil {
		t.Fatalf("set cache: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	_, ok, err := store.Get(ctx, "admin.roles", "k-expiry")
	if err != nil {
		t.Fatalf("get cache: %v", err)
	}
	if ok {
		t.Fatal("expected cache entry to expire")
	}
}

func TestNoopAdminListCacheStoreAlwaysMisses(t *testing.T) {
	store := NewNoopAdminListCacheStore()
	ctx := context.Background()
	if err := store.Set(ctx, "admin.permissions", "k", []byte(`{}`), time.Minute); err != nil {
		t.Fatalf("set noop cache: %v", err)
	}
	_, ok, err := store.Get(ctx, "admin.permissions", "k")
	if err != nil {
		t.Fatalf("get noop cache: %v", err)
	}
	if ok {
		t.Fatal("expected noop cache miss")
	}
	withAge := any(store).(AdminListCacheStoreWithAge)
	_, ok, age, err := withAge.GetWithAge(ctx, "admin.permissions", "k")
	if err != nil {
		t.Fatalf("get noop cache with age: %v", err)
	}
	if ok {
		t.Fatal("expected noop cache miss from GetWithAge")
	}
	if age != 0 {
		t.Fatalf("expected zero age from noop cache, got %v", age)
	}
	if err := store.InvalidateNamespace(ctx, "admin.permissions"); err != nil {
		t.Fatalf("invalidate noop cache: %v", err)
	}
}
