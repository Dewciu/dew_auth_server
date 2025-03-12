package cacherepositories_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dewciu/dew_auth_server/server/cacherepositories"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestRedisStore_Increment(t *testing.T) {
	t.Parallel()

	t.Run("first increment sets expiry", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		prefix := "ratelimit"
		store := cacherepositories.NewRedisStore(db, prefix)
		ctx := context.Background()

		// Test data
		key := "ip:127.0.0.1"
		fullKey := "ratelimit:ip:127.0.0.1"
		expiry := 60 * time.Second

		// First increment (returns 1)
		mock.ExpectIncr(fullKey).SetVal(1)
		// Should set expiry on first increment
		mock.ExpectExpire(fullKey, expiry).SetVal(true)

		// Execute
		count, err := store.Increment(ctx, key, expiry)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, 1, count)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("subsequent increment doesn't set expiry", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		prefix := "ratelimit"
		store := cacherepositories.NewRedisStore(db, prefix)
		ctx := context.Background()

		// Test data
		key := "ip:127.0.0.1"
		fullKey := "ratelimit:ip:127.0.0.1"
		expiry := 60 * time.Second

		// Subsequent increment (returns > 1)
		mock.ExpectIncr(fullKey).SetVal(2)
		// Should NOT set expiry on subsequent increments

		// Execute
		count, err := store.Increment(ctx, key, expiry)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, 2, count)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("increment error", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		prefix := "ratelimit"
		store := cacherepositories.NewRedisStore(db, prefix)
		ctx := context.Background()

		// Test data
		key := "ip:127.0.0.1"
		fullKey := "ratelimit:ip:127.0.0.1"
		expiry := 60 * time.Second

		// Create an error response
		mock.ExpectIncr(fullKey).SetErr(errors.New("test error"))

		// Execute
		count, err := store.Increment(ctx, key, expiry)

		// Assertions
		assert.Error(t, err)
		assert.Equal(t, 0, count)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("expire error", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		prefix := "ratelimit"
		store := cacherepositories.NewRedisStore(db, prefix)
		ctx := context.Background()

		// Test data
		key := "ip:127.0.0.1"
		fullKey := "ratelimit:ip:127.0.0.1"
		expiry := 60 * time.Second

		// First increment succeeds
		mock.ExpectIncr(fullKey).SetVal(1)

		// But expire fails
		mock.ExpectExpire(fullKey, expiry).SetErr(errors.New("test error"))

		// Execute
		count, err := store.Increment(ctx, key, expiry)

		// Assertions
		assert.Error(t, err)
		assert.Equal(t, 0, count) // Should return 0 on error

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
}

func TestRedisStore_Reset(t *testing.T) {
	t.Parallel()

	t.Run("successful reset", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		prefix := "ratelimit"
		store := cacherepositories.NewRedisStore(db, prefix)
		ctx := context.Background()

		// Test data
		key := "ip:127.0.0.1"
		fullKey := "ratelimit:ip:127.0.0.1"

		// Expect a delete operation
		mock.ExpectDel(fullKey).SetVal(1)

		// Execute
		err := store.Reset(ctx, key)

		// Assertions
		assert.NoError(t, err)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("reset error", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		prefix := "ratelimit"
		store := cacherepositories.NewRedisStore(db, prefix)
		ctx := context.Background()

		// Test data
		key := "ip:127.0.0.1"
		fullKey := "ratelimit:ip:127.0.0.1"

		// Create an error response
		mock.ExpectDel(fullKey).SetErr(errors.New("test error"))

		// Execute
		err := store.Reset(ctx, key)

		// Assertions
		assert.Error(t, err)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
}
