package cacherepositories_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/cacherepositories"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestAccessTokenRepository_Create(t *testing.T) {
	t.Parallel()
	// Setup
	db, mock := redismock.NewClientMock()
	ttl := 3600
	repo := cacherepositories.NewAccessTokenRepository(db, ttl)
	ctx := context.Background()

	// Test data
	tokenData := &cachemodels.AccessToken{
		Token:     "test-token",
		Scopes:    "read write",
		ClientID:  "client123",
		UserID:    "user456",
		TokenType: constants.TokenTypeBearer,
	}

	// Set expiration for token explicitly - necessary for test to match expected values
	// expTime := time.Now().Add(time.Duration(ttl) * time.Second)
	tokenData.SetExpiration(time.Duration(ttl) * time.Second)
	tokenData.SetIssuedTimeForNow()
	tokenData.SetNotBeforeForNow()

	// Set expectations
	// The token fields must match exactly what the repository will set
	expectedFields := map[string]interface{}{
		"tokenType": string(tokenData.TokenType),
		"clientID":  tokenData.ClientID,
		"userID":    tokenData.UserID,
		"scopes":    tokenData.Scopes,
		"exp":       tokenData.ExpiresIn,
		"iat":       tokenData.IssuedAt,
		"nbf":       tokenData.NotBefore,
		"aud":       tokenData.Audience,
		"sub":       tokenData.Subject,
		"iss":       tokenData.Issuer,
	}
	mock.ExpectHMSet("access_token:test-token", expectedFields).SetVal(true)

	// Index creation
	indexKey := "at_user_client_index:userID:user456:clientID:client123"
	mock.ExpectSAdd(indexKey, "test-token").SetVal(1)

	// Calculate expiry duration based on the token's expiration time
	expiryDuration := time.Until(time.Unix(int64(tokenData.ExpiresIn), 0))

	// Expirations
	mock.ExpectExpire(indexKey, expiryDuration).SetVal(true)
	mock.ExpectExpire("access_token:test-token", expiryDuration).SetVal(true)

	// Execute
	err := repo.Create(ctx, tokenData)

	// Assertions
	assert.NoError(t, err)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestAccessTokenRepository_GetByToken(t *testing.T) {
	t.Parallel()

	t.Run("token exists", func(t *testing.T) {
		t.Parallel()
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 3600
		repo := cacherepositories.NewAccessTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		token := "test-token"
		expTime := time.Now().Add(time.Hour).Unix()
		issuedTime := time.Now().Unix()
		notBeforeTime := time.Now().Unix()

		// Mock response
		mockData := map[string]string{
			"tokenType": string(constants.TokenTypeBearer),
			"clientID":  "client123",
			"userID":    "user456",
			"scopes":    "read write",
			"exp":       strconv.FormatInt(expTime, 10),
			"iat":       strconv.FormatInt(issuedTime, 10),
			"nbf":       strconv.FormatInt(notBeforeTime, 10),
			"aud":       "https://api.example.com",
			"sub":       "user456",
			"iss":       "https://auth.example.com",
		}
		mock.ExpectHGetAll("access_token:test-token").SetVal(mockData)

		// Execute
		accessToken, err := repo.GetByToken(ctx, token)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, accessToken)
		assert.Equal(t, token, accessToken.Token)
		assert.Equal(t, "client123", accessToken.ClientID)
		assert.Equal(t, "user456", accessToken.UserID)
		assert.Equal(t, "read write", accessToken.Scopes)
		assert.Equal(t, constants.TokenTypeBearer, accessToken.TokenType)
		assert.Equal(t, "https://api.example.com", accessToken.Audience)
		assert.Equal(t, "user456", accessToken.Subject)
		assert.Equal(t, "https://auth.example.com", accessToken.Issuer)
		assert.Equal(t, int(expTime), accessToken.ExpiresIn)
		assert.Equal(t, int(issuedTime), accessToken.IssuedAt)
		assert.Equal(t, int(notBeforeTime), accessToken.NotBefore)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("token does not exist", func(t *testing.T) {
		t.Parallel()
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 3600
		repo := cacherepositories.NewAccessTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		token := "test-token"

		// Empty response
		mock.ExpectHGetAll("access_token:test-token").SetVal(map[string]string{})

		// Execute
		accessToken, err := repo.GetByToken(ctx, token)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, accessToken)
		assert.Contains(t, err.Error(), "access token is invalid or expired")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("redis error", func(t *testing.T) {
		t.Parallel()
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 3600
		repo := cacherepositories.NewAccessTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		token := "test-token"

		// Error response
		mock.ExpectHGetAll("access_token:test-token").SetErr(errors.New("someRedisError"))

		// Execute
		accessToken, err := repo.GetByToken(ctx, token)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, accessToken)
		assert.Contains(t, err.Error(), "access token is invalid or expired")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
}

func TestAccessTokenRepository_GetByUserAndClient(t *testing.T) {
	t.Parallel()

	t.Run("tokens exist", func(t *testing.T) {
		t.Parallel()
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 3600
		repo := cacherepositories.NewAccessTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		userID := "user456"
		clientID := "client123"
		indexKey := "at_user_client_index:userID:user456:clientID:client123"

		// Mock responses
		mock.ExpectSMembers(indexKey).SetVal([]string{"token1", "token2"})

		// Mock token1 data
		token1Data := map[string]string{
			"tokenType": string(constants.TokenTypeBearer),
			"clientID":  clientID,
			"userID":    userID,
			"scopes":    "read",
			"exp":       strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
			"iat":       strconv.FormatInt(time.Now().Unix(), 10),
			"nbf":       strconv.FormatInt(time.Now().Unix(), 10),
		}
		mock.ExpectHGetAll("access_token:token1").SetVal(token1Data)

		// Mock token2 data
		token2Data := map[string]string{
			"tokenType": string(constants.TokenTypeBearer),
			"clientID":  clientID,
			"userID":    userID,
			"scopes":    "write",
			"exp":       strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
			"iat":       strconv.FormatInt(time.Now().Unix(), 10),
			"nbf":       strconv.FormatInt(time.Now().Unix(), 10),
		}
		mock.ExpectHGetAll("access_token:token2").SetVal(token2Data)

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
		t.Parallel()
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 3600
		repo := cacherepositories.NewAccessTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		userID := "user456"
		clientID := "client123"
		indexKey := "at_user_client_index:userID:user456:clientID:client123"

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
		t.Parallel()
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 3600
		repo := cacherepositories.NewAccessTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		userID := "user456"
		clientID := "client123"
		indexKey := "at_user_client_index:userID:user456:clientID:client123"

		// Error response
		mock.ExpectSMembers(indexKey).SetErr(errors.New("someRedisError"))

		// Execute
		tokens, err := repo.GetByUserAndClient(ctx, userID, clientID)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, tokens)
		assert.Contains(t, err.Error(), "failed to get access tokens by user and client index")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("token retrieval error", func(t *testing.T) {
		t.Parallel()
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 3600
		repo := cacherepositories.NewAccessTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		userID := "user456"
		clientID := "client123"
		indexKey := "at_user_client_index:userID:user456:clientID:client123"

		// Mock successful index but error on token retrieval
		mock.ExpectSMembers(indexKey).SetVal([]string{"token1"})

		// Error on token retrieval
		mock.ExpectHGetAll("access_token:token1").SetErr(errors.New("someRedisError"))

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

func TestAccessTokenRepository_Update(t *testing.T) {
	t.Parallel()

	t.Run("successful update", func(t *testing.T) {
		t.Parallel()
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 3600
		repo := cacherepositories.NewAccessTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		tokenData := &cachemodels.AccessToken{
			Token:     "test-token",
			Scopes:    "read write",
			ClientID:  "client123",
			UserID:    "user456",
			TokenType: constants.TokenTypeBearer,
		}

		// Expect a delete operation
		mock.ExpectDel("access_token:test-token").SetVal(1)

		// Execute
		err := repo.Update(ctx, tokenData)

		// Assertions
		assert.NoError(t, err)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("redis error", func(t *testing.T) {
		t.Parallel()
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 3600
		repo := cacherepositories.NewAccessTokenRepository(db, ttl)
		ctx := context.Background()

		// Test data
		tokenData := &cachemodels.AccessToken{
			Token:     "test-token",
			Scopes:    "read write",
			ClientID:  "client123",
			UserID:    "user456",
			TokenType: constants.TokenTypeBearer,
		}

		// Mock an error response
		mock.ExpectDel("access_token:test-token").SetErr(errors.New("someRedisError"))

		// Execute
		err := repo.Update(ctx, tokenData)

		// Assertions
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete access token")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
}
