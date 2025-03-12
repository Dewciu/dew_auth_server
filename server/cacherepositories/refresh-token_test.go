package cacherepositories

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestRefreshTokenRepository_Create(t *testing.T) {
	t.Parallel()
	// Setup
	db, mock := redismock.NewClientMock()
	ttl := 2592000 // 30 days in seconds
	repo := NewRefreshTokenRepository(db, ttl)
	ctx := context.Background()

	// Test data
	tokenData := &cachemodels.RefreshToken{
		Token:    "test-refresh-token",
		Scopes:   "read write",
		ClientID: "client123",
		UserID:   "user456",
	}

	tokenData.SetExpiration(time.Duration(ttl) * time.Second)
	tokenData.SetIssuedTimeForNow()

	// Set expectations
	expectedFields := map[string]interface{}{
		"clientID": tokenData.ClientID,
		"userID":   tokenData.UserID,
		"scopes":   tokenData.Scopes,
		"exp":      tokenData.ExpiresIn,
		"iat":      tokenData.IssuedAt,
		"revoked":  tokenData.Revoked,
	}
	mock.ExpectHMSet("refresh_token:test-refresh-token", expectedFields).SetVal(true)

	// Index creation
	indexKey := "rt_user_client_index:userID:user456:clientID:client123"
	mock.ExpectSAdd(indexKey, "test-refresh-token").SetVal(1)

	// Calculate expiry duration based on the token's expiration time
	expiryDuration := time.Until(time.Unix(int64(tokenData.ExpiresIn), 0))

	// Expirations
	mock.ExpectExpire(indexKey, expiryDuration).SetVal(true)
	mock.ExpectExpire("refresh_token:test-refresh-token", expiryDuration).SetVal(true)
	// Execute
	err := repo.Create(ctx, tokenData)

	// Assertions
	assert.NoError(t, err)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestRefreshTokenRepository_GetByToken(t *testing.T) {
	t.Parallel()

	t.Run("token exists", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 2592000 // 30 days in seconds
		repo := NewRefreshTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		token := "test-refresh-token"
		expTime := time.Now().Add(24 * time.Hour).Unix()
		issuedTime := time.Now().Unix()

		// Mock data
		mockData := map[string]string{
			"clientID": "client123",
			"userID":   "user456",
			"scopes":   "read write",
			"exp":      strconv.FormatInt(expTime, 10),
			"iat":      strconv.FormatInt(issuedTime, 10),
			"revoked":  "false",
		}

		// Set expectation
		mock.ExpectHGetAll("refresh_token:test-refresh-token").SetVal(mockData)

		// Execute
		refreshToken, err := repo.GetByToken(ctx, token)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, refreshToken)
		assert.Equal(t, token, refreshToken.Token)
		assert.Equal(t, "client123", refreshToken.ClientID)
		assert.Equal(t, "user456", refreshToken.UserID)
		assert.Equal(t, "read write", refreshToken.Scopes)
		assert.Equal(t, int(expTime), refreshToken.ExpiresIn)
		assert.Equal(t, int(issuedTime), refreshToken.IssuedAt)
		assert.False(t, refreshToken.Revoked)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("token does not exist", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 2592000 // 30 days in seconds
		repo := NewRefreshTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		token := "test-refresh-token"

		// Empty response
		mock.ExpectHGetAll("refresh_token:test-refresh-token").SetVal(map[string]string{})

		// Execute
		refreshToken, err := repo.GetByToken(ctx, token)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, refreshToken)
		assert.Contains(t, err.Error(), "access token is invalid or expired") // This message needs updating in the actual code

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("redis error", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 2592000 // 30 days in seconds
		repo := NewRefreshTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		token := "test-refresh-token"

		// Error response
		mock.ExpectHGetAll("refresh_token:test-refresh-token").SetErr(errors.New("redis error"))

		// Execute
		refreshToken, err := repo.GetByToken(ctx, token)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, refreshToken)
		assert.Contains(t, err.Error(), "access token is invalid or expired") // This message needs updating in the actual code

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("invalid expiration time", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 2592000 // 30 days in seconds
		repo := NewRefreshTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		token := "test-refresh-token"

		// Mock data with invalid exp
		mockData := map[string]string{
			"clientID": "client123",
			"userID":   "user456",
			"scopes":   "read write",
			"exp":      "not-a-number",
			"iat":      strconv.FormatInt(time.Now().Unix(), 10),
		}

		// Set expectation
		mock.ExpectHGetAll("refresh_token:test-refresh-token").SetVal(mockData)

		// Execute
		refreshToken, err := repo.GetByToken(ctx, token)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, refreshToken)
		assert.Contains(t, err.Error(), "failed to parse expiration time")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("invalid issued at time", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 2592000 // 30 days in seconds
		repo := NewRefreshTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		token := "test-refresh-token"

		// Mock data with invalid iat
		mockData := map[string]string{
			"clientID": "client123",
			"userID":   "user456",
			"scopes":   "read write",
			"exp":      strconv.FormatInt(time.Now().Add(24*time.Hour).Unix(), 10),
			"iat":      "not-a-number",
		}

		// Set expectation
		mock.ExpectHGetAll("refresh_token:test-refresh-token").SetVal(mockData)

		// Execute
		refreshToken, err := repo.GetByToken(ctx, token)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, refreshToken)
		assert.Contains(t, err.Error(), "failed to parse issued time")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
}

func TestRefreshTokenRepository_GetByUserAndClient(t *testing.T) {
	t.Parallel()

	t.Run("tokens exist", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 2592000 // 30 days in seconds
		repo := NewRefreshTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		userID := "user456"
		clientID := "client123"
		indexKey := "rt_user_client_index:userID:user456:clientID:client123"

		// Mock responses
		mock.ExpectSMembers(indexKey).SetVal([]string{"token1", "token2"})

		// Mock token1 data
		token1Data := map[string]string{
			"clientID": clientID,
			"userID":   userID,
			"scopes":   "read",
			"exp":      strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
			"iat":      strconv.FormatInt(time.Now().Unix(), 10),
		}
		mock.ExpectHGetAll("refresh_token:token1").SetVal(token1Data)

		// Mock token2 data
		token2Data := map[string]string{
			"clientID": clientID,
			"userID":   userID,
			"scopes":   "write",
			"exp":      strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
			"iat":      strconv.FormatInt(time.Now().Unix(), 10),
		}
		mock.ExpectHGetAll("refresh_token:token2").SetVal(token2Data)

		// Execute
		tokens, err := repo.GetByUserAndClient(ctx, userID, clientID)

		// Assertions
		assert.NoError(t, err)
		assert.Len(t, tokens, 2)
		assert.Equal(t, "token1", tokens[0].Token)
		assert.Equal(t, "read", tokens[0].Scopes)
		assert.Equal(t, "token2", tokens[1].Token)
		assert.Equal(t, "write", tokens[1].Scopes)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("no tokens found", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 2592000 // 30 days in seconds
		repo := NewRefreshTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		userID := "user456"
		clientID := "client123"
		indexKey := "rt_user_client_index:userID:user456:clientID:client123"

		// Empty result
		mock.ExpectSMembers(indexKey).SetVal([]string{})

		// Execute
		tokens, err := repo.GetByUserAndClient(ctx, userID, clientID)

		// Assertions
		assert.NoError(t, err)
		assert.Empty(t, tokens)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("redis error", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 2592000 // 30 days in seconds
		repo := NewRefreshTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		userID := "user456"
		clientID := "client123"
		indexKey := "rt_user_client_index:userID:user456:clientID:client123"

		// Error response
		mock.ExpectSMembers(indexKey).SetErr(errors.New("redis error"))

		// Execute
		tokens, err := repo.GetByUserAndClient(ctx, userID, clientID)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, tokens)
		assert.Contains(t, err.Error(), "failed to get access tokens by user")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("token retrieval error", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 2592000 // 30 days in seconds
		repo := NewRefreshTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		userID := "user456"
		clientID := "client123"
		indexKey := "rt_user_client_index:userID:user456:clientID:client123"

		// Mock successful index but error on token retrieval
		mock.ExpectSMembers(indexKey).SetVal([]string{"token1"})

		// Error on token retrieval
		mock.ExpectHGetAll("refresh_token:token1").SetErr(errors.New("redis error"))

		// Execute
		tokens, err := repo.GetByUserAndClient(ctx, userID, clientID)

		// Assertions
		assert.NoError(t, err)  // Overall operation should still succeed
		assert.Empty(t, tokens) // But no tokens should be returned

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
}
