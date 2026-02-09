package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisAdminListCacheStore struct {
	client redis.UniversalClient
	prefix string
}

func NewRedisAdminListCacheStore(client redis.UniversalClient, prefix string) *RedisAdminListCacheStore {
	if prefix == "" {
		prefix = "admin_list_cache"
	}
	return &RedisAdminListCacheStore{
		client: client,
		prefix: prefix,
	}
}

func (s *RedisAdminListCacheStore) Get(ctx context.Context, namespace, key string) ([]byte, bool, error) {
	if s.client == nil {
		return nil, false, nil
	}
	value, err := s.client.Get(ctx, s.dataKey(namespace, key)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (s *RedisAdminListCacheStore) Set(ctx context.Context, namespace, key string, value []byte, ttl time.Duration) error {
	if s.client == nil || ttl <= 0 {
		return nil
	}
	dataKey := s.dataKey(namespace, key)
	namespaceIndex := s.namespaceIndexKey(namespace)
	pipe := s.client.TxPipeline()
	pipe.Set(ctx, dataKey, value, ttl)
	pipe.SAdd(ctx, namespaceIndex, dataKey)
	pipe.Expire(ctx, namespaceIndex, ttl+time.Minute)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisAdminListCacheStore) InvalidateNamespace(ctx context.Context, namespace string) error {
	if s.client == nil {
		return nil
	}
	namespaceIndex := s.namespaceIndexKey(namespace)
	keys, err := s.client.SMembers(ctx, namespaceIndex).Result()
	if err != nil && err != redis.Nil {
		return err
	}
	pipe := s.client.TxPipeline()
	if len(keys) > 0 {
		pipe.Del(ctx, keys...)
	}
	pipe.Del(ctx, namespaceIndex)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisAdminListCacheStore) dataKey(namespace, key string) string {
	return fmt.Sprintf("%s:data:%s:%s", s.prefix, normalizeToken(namespace), hashToken(key))
}

func (s *RedisAdminListCacheStore) namespaceIndexKey(namespace string) string {
	return fmt.Sprintf("%s:index:%s", s.prefix, normalizeToken(namespace))
}

func normalizeToken(v string) string {
	if v == "" {
		return "default"
	}
	return v
}

func hashToken(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
