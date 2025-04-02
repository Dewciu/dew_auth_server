package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRefreshTokenRepository is a mock implementation of the IRefreshTokenRepository interface
type MockRefreshTokenRepository struct {
	mock.Mock
}

func (m *MockRefreshTokenRepository) Create(ctx context.Context, tokenData *cachemodels.RefreshToken) error {
	args := m.Called(ctx, tokenData)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) GetByToken(ctx context.Context, token string) (*cachemodels.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cachemodels.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) GetByUserAndClient(ctx context.Context, userID string, clientID string) ([]*cachemodels.RefreshToken, error) {
	args := m.Called(ctx, userID, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*cachemodels.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) Update(ctx context.Context, tokenData *cachemodels.RefreshToken) error {
	args := m.Called(ctx, tokenData)
	return args.Error(0)
}

func TestGenerateOpaqueToken(t *testing.T) {
	t.Parallel()
	mockRepo := new(MockRefreshTokenRepository)
	service := services.NewRefreshTokenService(mockRepo)

	t.Run("valid token generation", func(t *testing.T) {
		t.Parallel()
		token, err := service.GenerateOpaqueToken(32)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.GreaterOrEqual(t, len(token), 32) // Base64 encoding increases length
	})

	t.Run("invalid length", func(t *testing.T) {
		t.Parallel()
		token, err := service.GenerateOpaqueToken(0)
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "invalid token length")
	})
}

func TestCreateRefreshToken(t *testing.T) {
	t.Parallel()

	clientID := "client123"
	userID := "user456"
	scope := "read write"
	tokenLength := 32

	t.Run("create new refresh token", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup: No existing token
		mockRepo.On("GetByUserAndClient", ctx, userID, clientID).Return([]*cachemodels.RefreshToken{}, nil).Once()

		// The token will be generated randomly, so we can't know its exact value
		mockRepo.On("Create", ctx, mock.MatchedBy(func(token *cachemodels.RefreshToken) bool {
			return token.ClientID == clientID && token.UserID == userID && token.Scopes == scope
		})).Return(nil).Once()

		// Execute
		token, err := service.CreateRefreshToken(ctx, clientID, userID, scope, tokenLength)

		// Verify
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		mockRepo.AssertExpectations(t)
	})

	t.Run("reuse existing refresh token", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup: Existing token
		existingToken := &cachemodels.RefreshToken{
			Token:     "existing_token",
			ClientID:  clientID,
			UserID:    userID,
			Scopes:    scope,
			ExpiresIn: int(time.Now().Add(1 * time.Hour).Unix()), // Not expired
		}
		mockRepo.On("GetByUserAndClient", ctx, userID, clientID).
			Return([]*cachemodels.RefreshToken{existingToken}, nil).Once()

		// Execute
		token, err := service.CreateRefreshToken(ctx, clientID, userID, scope, tokenLength)

		// Verify
		assert.NoError(t, err)
		assert.Equal(t, existingToken.Token, token)
		mockRepo.AssertExpectations(t)
	})

	t.Run("error getting existing tokens", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		mockRepo.On("GetByUserAndClient", ctx, userID, clientID).
			Return(nil, errors.New("database error")).Once()

		// Execute
		token, err := service.CreateRefreshToken(ctx, clientID, userID, scope, tokenLength)

		// Verify
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "failed to get existing refresh token")
		mockRepo.AssertExpectations(t)
	})

	t.Run("error creating token", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup: No existing token
		mockRepo.On("GetByUserAndClient", ctx, userID, clientID).
			Return([]*cachemodels.RefreshToken{}, nil).Once()

		// Fail on create
		mockRepo.On("Create", ctx, mock.AnythingOfType("*cachemodels.RefreshToken")).
			Return(errors.New("create error")).Once()

		// Execute
		token, err := service.CreateRefreshToken(ctx, clientID, userID, scope, tokenLength)

		// Verify
		assert.Error(t, err)
		assert.Empty(t, token)
		mockRepo.AssertExpectations(t)
	})
}

func TestGetTokenDetails(t *testing.T) {
	t.Parallel()
	tokenStr := "test_token"

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		expectedToken := &cachemodels.RefreshToken{
			Token:     tokenStr,
			ClientID:  "client123",
			UserID:    "user456",
			Scopes:    "read write",
			ExpiresIn: int(time.Now().Add(1 * time.Hour).Unix()),
		}
		mockRepo.On("GetByToken", ctx, tokenStr).Return(expectedToken, nil).Once()

		// Execute
		token, err := service.GetTokenDetails(ctx, tokenStr)

		// Verify
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, token)
		mockRepo.AssertExpectations(t)
	})

	t.Run("token not found", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		mockRepo.On("GetByToken", ctx, tokenStr).
			Return(nil, errors.New("token not found")).Once()

		// Execute
		token, err := service.GetTokenDetails(ctx, tokenStr)

		// Verify
		assert.Error(t, err)
		assert.Nil(t, token)
		assert.IsType(t, serviceerrors.TokenNotFoundError{}, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestRevokeToken(t *testing.T) {
	t.Parallel()
	t.Run("successful revocation", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		token := &cachemodels.RefreshToken{
			Token:     "test_token",
			ClientID:  "client123",
			UserID:    "user456",
			Scopes:    "read write",
			ExpiresIn: int(time.Now().Add(1 * time.Hour).Unix()),
			Revoked:   false,
		}

		// The token should be revoked when passed to Create
		mockRepo.On("Update", ctx, mock.MatchedBy(func(t *cachemodels.RefreshToken) bool {
			return t.Revoked == true
		})).Return(nil).Once()

		// Execute
		err := service.RevokeToken(ctx, token)

		// Verify
		assert.NoError(t, err)
		assert.True(t, token.Revoked)
		mockRepo.AssertExpectations(t)
	})

	t.Run("error on revocation", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		token := &cachemodels.RefreshToken{
			Token:     "test_token",
			ClientID:  "client123",
			UserID:    "user456",
			Scopes:    "read write",
			ExpiresIn: int(time.Now().Add(1 * time.Hour).Unix()),
			Revoked:   false,
		}

		mockRepo.On("Update", ctx, mock.AnythingOfType("*cachemodels.RefreshToken")).
			Return(errors.New("update error")).Once()

		// Execute
		err := service.RevokeToken(ctx, token)

		// Verify
		assert.Error(t, err)
		assert.True(t, token.Revoked) // Token should still be marked as revoked
		mockRepo.AssertExpectations(t)
	})
}

func TestGetExistingRefreshToken(t *testing.T) {
	t.Parallel()

	clientID := "client123"
	userID := "user456"

	t.Run("no tokens found", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		mockRepo.On("GetByUserAndClient", ctx, userID, clientID).
			Return([]*cachemodels.RefreshToken{}, nil).Once()

		// Execute
		token, err := service.(*services.RefreshTokenService).GetExistingRefreshToken(ctx, clientID, userID)

		// Verify
		assert.NoError(t, err)
		assert.Nil(t, token)
		mockRepo.AssertExpectations(t)
	})

	t.Run("one active token found", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		activeToken := &cachemodels.RefreshToken{
			Token:     "active_token",
			ClientID:  clientID,
			UserID:    userID,
			Scopes:    "read write",
			ExpiresIn: int(time.Now().Add(1 * time.Hour).Unix()),
			Revoked:   false,
		}
		mockRepo.On("GetByUserAndClient", ctx, userID, clientID).
			Return([]*cachemodels.RefreshToken{activeToken}, nil).Once()

		// Execute
		token, err := service.(*services.RefreshTokenService).GetExistingRefreshToken(ctx, clientID, userID)

		// Verify
		assert.NoError(t, err)
		assert.Equal(t, activeToken, token)
		mockRepo.AssertExpectations(t)
	})

	t.Run("multiple active tokens error", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		token1 := &cachemodels.RefreshToken{
			Token:     "token1",
			ClientID:  clientID,
			UserID:    userID,
			ExpiresIn: int(time.Now().Add(1 * time.Hour).Unix()),
			Revoked:   false,
		}
		token2 := &cachemodels.RefreshToken{
			Token:     "token2",
			ClientID:  clientID,
			UserID:    userID,
			ExpiresIn: int(time.Now().Add(1 * time.Hour).Unix()),
			Revoked:   false,
		}
		mockRepo.On("GetByUserAndClient", ctx, userID, clientID).
			Return([]*cachemodels.RefreshToken{token1, token2}, nil).Once()

		// Execute
		token, err := service.(*services.RefreshTokenService).GetExistingRefreshToken(ctx, clientID, userID)

		// Verify
		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "multiple active refresh tokens")
		mockRepo.AssertExpectations(t)
	})

	t.Run("error from repository", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		mockRepo.On("GetByUserAndClient", ctx, userID, clientID).
			Return(nil, errors.New("repository error")).Once()

		// Execute
		token, err := service.(*services.RefreshTokenService).GetExistingRefreshToken(ctx, clientID, userID)

		// Verify
		assert.Error(t, err)
		assert.Nil(t, token)
		mockRepo.AssertExpectations(t)
	})

	t.Run("filter inactive tokens", func(t *testing.T) {
		t.Parallel()
		mockRepo := new(MockRefreshTokenRepository)
		service := services.NewRefreshTokenService(mockRepo)
		ctx := context.Background()
		// Setup
		expiredToken := &cachemodels.RefreshToken{
			Token:     "expired_token",
			ClientID:  clientID,
			UserID:    userID,
			ExpiresIn: int(time.Now().Add(-1 * time.Hour).Unix()), // Expired
			Revoked:   false,
		}
		revokedToken := &cachemodels.RefreshToken{
			Token:     "revoked_token",
			ClientID:  clientID,
			UserID:    userID,
			ExpiresIn: int(time.Now().Add(1 * time.Hour).Unix()),
			Revoked:   true, // Revoked
		}
		activeToken := &cachemodels.RefreshToken{
			Token:     "active_token",
			ClientID:  clientID,
			UserID:    userID,
			ExpiresIn: int(time.Now().Add(1 * time.Hour).Unix()),
			Revoked:   false,
		}

		mockRepo.On("GetByUserAndClient", ctx, userID, clientID).
			Return([]*cachemodels.RefreshToken{expiredToken, revokedToken, activeToken}, nil).Once()

		// Execute
		token, err := service.(*services.RefreshTokenService).GetExistingRefreshToken(ctx, clientID, userID)

		// Verify
		assert.NoError(t, err)
		assert.Equal(t, activeToken, token)
		mockRepo.AssertExpectations(t)
	})
}
