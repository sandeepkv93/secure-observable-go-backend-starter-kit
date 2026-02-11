package service

import (
	"context"
	"sync"
	"time"
)

type AdminListCacheStore interface {
	Get(ctx context.Context, namespace, key string) ([]byte, bool, error)
	Set(ctx context.Context, namespace, key string, value []byte, ttl time.Duration) error
	InvalidateNamespace(ctx context.Context, namespace string) error
}

type AdminListCacheStoreWithAge interface {
	AdminListCacheStore
	GetWithAge(ctx context.Context, namespace, key string) ([]byte, bool, time.Duration, error)
}

type NoopAdminListCacheStore struct{}

func NewNoopAdminListCacheStore() *NoopAdminListCacheStore {
	return &NoopAdminListCacheStore{}
}

func (s *NoopAdminListCacheStore) Get(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, nil
}

func (s *NoopAdminListCacheStore) GetWithAge(context.Context, string, string) ([]byte, bool, time.Duration, error) {
	return nil, false, 0, nil
}

func (s *NoopAdminListCacheStore) Set(context.Context, string, string, []byte, time.Duration) error {
	return nil
}

func (s *NoopAdminListCacheStore) InvalidateNamespace(context.Context, string) error {
	return nil
}

type memoryCacheEntry struct {
	payload   []byte
	createdAt time.Time
	expiresAt time.Time
}

type InMemoryAdminListCacheStore struct {
	mu    sync.RWMutex
	store map[string]map[string]memoryCacheEntry
}

func NewInMemoryAdminListCacheStore() *InMemoryAdminListCacheStore {
	return &InMemoryAdminListCacheStore{
		store: make(map[string]map[string]memoryCacheEntry),
	}
}

func (s *InMemoryAdminListCacheStore) Get(_ context.Context, namespace, key string) ([]byte, bool, error) {
	payload, ok, _, err := s.GetWithAge(context.Background(), namespace, key)
	return payload, ok, err
}

func (s *InMemoryAdminListCacheStore) GetWithAge(_ context.Context, namespace, key string) ([]byte, bool, time.Duration, error) {
	now := time.Now().UTC()
	s.mu.RLock()
	ns, ok := s.store[namespace]
	if !ok {
		s.mu.RUnlock()
		return nil, false, 0, nil
	}
	entry, ok := ns[key]
	s.mu.RUnlock()
	if !ok {
		return nil, false, 0, nil
	}
	if now.After(entry.expiresAt) {
		s.mu.Lock()
		if ns2, ok2 := s.store[namespace]; ok2 {
			delete(ns2, key)
			if len(ns2) == 0 {
				delete(s.store, namespace)
			}
		}
		s.mu.Unlock()
		return nil, false, 0, nil
	}
	age := now.Sub(entry.createdAt)
	if age < 0 {
		age = 0
	}
	return append([]byte(nil), entry.payload...), true, age, nil
}

func (s *InMemoryAdminListCacheStore) Set(_ context.Context, namespace, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ns, ok := s.store[namespace]
	if !ok {
		ns = make(map[string]memoryCacheEntry)
		s.store[namespace] = ns
	}
	ns[key] = memoryCacheEntry{
		payload:   append([]byte(nil), value...),
		createdAt: time.Now().UTC(),
		expiresAt: time.Now().UTC().Add(ttl),
	}
	return nil
}

func (s *InMemoryAdminListCacheStore) InvalidateNamespace(_ context.Context, namespace string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, namespace)
	return nil
}
