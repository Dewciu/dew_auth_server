package cacherepositories

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// LimiterStore defines different storage mechanisms for rate limiting
type LimiterStore interface {
	Increment(ctx context.Context, key string, expiry time.Duration) (int, error)
	Reset(ctx context.Context, key string) error
}

// RedisStore implements LimiterStore using Redis
type RedisStore struct {
	client *redis.Client
	prefix string
}

// NewRedisStore creates a new Redis-backed store for rate limiting
func NewRedisStore(client *redis.Client, prefix string) *RedisStore {
	return &RedisStore{
		client: client,
		prefix: prefix,
	}
}

// Increment increments the counter for the given key, returning the current count and error
func (s *RedisStore) Increment(ctx context.Context, key string, expiry time.Duration) (int, error) {
	key = fmt.Sprintf("%s:%s", s.prefix, key)

	val, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	if val == 1 {
		_, err = s.client.Expire(ctx, key, expiry).Result()
		if err != nil {
			return 0, err
		}
	}

	return int(val), nil
}

// Reset clears the rate limit counters for the given key
func (s *RedisStore) Reset(ctx context.Context, key string) error {
	key = fmt.Sprintf("%s:%s", s.prefix, key)
	_, err := s.client.Del(ctx, key).Result()
	return err
}
