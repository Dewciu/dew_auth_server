package cacherepositories_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/cacherepositories"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizationCodeRepository_Create(t *testing.T) {
	t.Parallel()
	// Setup
	db, mock := redismock.NewClientMock()
	ttl := 600 // 10 minutes
	repo := cacherepositories.NewAuthorizationCodeRepository(db, ttl)
	ctx := context.Background()

	// Test data
	codeData := &cachemodels.AuthorizationCode{
		Code:                "test-auth-code",
		UserID:              "user456",
		ClientID:            "client123",
		RedirectURI:         "https://example.com/callback",
		Scopes:              "read write",
		CodeChallenge:       "code-challenge",
		CodeChallengeMethod: string(constants.SHA256Method),
	}

	// Set expectations for the mock
	expectedFields := map[string]interface{}{
		"userID":              codeData.UserID,
		"clientID":            codeData.ClientID,
		"redirectURI":         codeData.RedirectURI,
		"scopes":              codeData.Scopes,
		"codeChallenge":       codeData.CodeChallenge,
		"codeChallengeMethod": codeData.CodeChallengeMethod,
	}
	mock.ExpectHMSet("authorization_code:test-auth-code", expectedFields).SetVal(true)

	// Expiration
	mock.ExpectExpire("authorization_code:test-auth-code", time.Duration(ttl)*time.Second).SetVal(true)

	// Execute
	err := repo.Create(ctx, codeData)

	// Assertions
	assert.NoError(t, err)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestAuthorizationCodeRepository_GetByCode(t *testing.T) {
	t.Parallel()

	t.Run("code exists", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 600 // 10 minutes
		repo := cacherepositories.NewAuthorizationCodeRepository(db, ttl)
		ctx := context.Background()

		// Test data
		code := "test-auth-code"

		// Mock data
		mockData := map[string]string{
			"userID":              "user456",
			"clientID":            "client123",
			"redirectURI":         "https://example.com/callback",
			"scopes":              "read write",
			"codeChallenge":       "code-challenge",
			"codeChallengeMethod": string(constants.SHA256Method),
		}

		// Set expectation
		mock.ExpectHGetAll("authorization_code:test-auth-code").SetVal(mockData)

		// Execute
		authCode, err := repo.GetByCode(ctx, code)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, authCode)
		assert.Equal(t, code, authCode.Code)
		assert.Equal(t, "user456", authCode.UserID)
		assert.Equal(t, "client123", authCode.ClientID)
		assert.Equal(t, "https://example.com/callback", authCode.RedirectURI)
		assert.Equal(t, "read write", authCode.Scopes)
		assert.Equal(t, "code-challenge", authCode.CodeChallenge)
		assert.Equal(t, string(constants.SHA256Method), authCode.CodeChallengeMethod)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("code does not exist", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 600 // 10 minutes
		repo := cacherepositories.NewAuthorizationCodeRepository(db, ttl)
		ctx := context.Background()

		// Test data
		code := "test-auth-code"

		// Empty response
		mock.ExpectHGetAll("authorization_code:test-auth-code").SetVal(map[string]string{})

		// Execute
		authCode, err := repo.GetByCode(ctx, code)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, authCode)
		assert.Contains(t, err.Error(), "authorization is invalid or expired")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("redis error", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 600 // 10 minutes
		repo := cacherepositories.NewAuthorizationCodeRepository(db, ttl)
		ctx := context.Background()

		// Test data
		code := "test-auth-code"

		// Error response
		mock.ExpectHGetAll("authorization_code:test-auth-code").SetErr(errors.New("failed to get authorization code"))

		// Execute
		authCode, err := repo.GetByCode(ctx, code)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, authCode)
		assert.Contains(t, err.Error(), "authorization is invalid or expired")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("missing required fields", func(t *testing.T) {
		// Setup
		db, mock := redismock.NewClientMock()
		ttl := 600 // 10 minutes
		repo := cacherepositories.NewAuthorizationCodeRepository(db, ttl)
		ctx := context.Background()

		// Test data
		code := "test-auth-code"

		// Mock data with missing fields
		mockData := map[string]string{
			"userID":   "user456",
			"clientID": "client123",
			// Missing redirectURI
			"scopes": "read write",
			// Missing codeChallenge
			"codeChallengeMethod": string(constants.SHA256Method),
		}

		// Set expectation
		mock.ExpectHGetAll("authorization_code:test-auth-code").SetVal(mockData)

		// Execute
		authCode, err := repo.GetByCode(ctx, code)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, authCode)
		// Should fail validation due to missing fields
		assert.Contains(t, err.Error(), "redirect URI is required")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
}
