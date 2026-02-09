package health

import (
	"context"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type DBChecker struct {
	db *gorm.DB
}

func NewDBChecker(db *gorm.DB) Checker {
	if db == nil {
		return nil
	}
	return &DBChecker{db: db}
}

func (c *DBChecker) Check(ctx context.Context) CheckResult {
	res := CheckResult{Name: "db", Healthy: true}
	if c.db == nil {
		res.Healthy = false
		res.Error = "db not configured"
		return res
	}
	sqlDB, err := c.db.DB()
	if err != nil {
		res.Healthy = false
		res.Error = err.Error()
		return res
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		res.Healthy = false
		res.Error = err.Error()
	}
	return res
}

type RedisChecker struct {
	client redis.UniversalClient
}

func NewRedisChecker(client redis.UniversalClient) Checker {
	if client == nil {
		return nil
	}
	return &RedisChecker{client: client}
}

func (c *RedisChecker) Check(ctx context.Context) CheckResult {
	res := CheckResult{Name: "redis", Healthy: true}
	if c.client == nil {
		res.Healthy = false
		res.Error = "redis not configured"
		return res
	}
	if err := c.client.Ping(ctx).Err(); err != nil {
		res.Healthy = false
		res.Error = err.Error()
	}
	return res
}
