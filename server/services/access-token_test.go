package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAccessTokenRepository is a mock implementation of the IAccessTokenRepository interface
type MockAccessTokenRepository struct {
	mock.Mock
}

func (m *MockAccessTokenRepository) Create(ctx context.Context, tokenData *cachemodels.AccessToken) error {
	args := m.Called(ctx, tokenData)
	return args.Error(0)
}

func (m *MockAccessTokenRepository) GetByToken(ctx context.Context, token string) (*cachemodels.AccessToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cachemodels.AccessToken), args.Error(1)
}

func (m *MockAccessTokenRepository) GetByUserAndClient(ctx context.Context, userID string, clientID string) ([]*cachemodels.AccessToken, error) {
	args := m.Called(ctx, userID, clientID)
	return args.Get(0).([]*cachemodels.AccessToken), args.Error(1)
}

func (m *MockAccessTokenRepository) Update(ctx context.Context, tokenData *cachemodels.AccessToken) error {
	args := m.Called(ctx, tokenData)
	return args.Error(0)
}

func TestGenerateOpaqueToken_Success(t *testing.T) {
	t.Parallel()
	// Setup
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	// Execute
	token, err := accessTokenService.GenerateOpaqueToken(32)

	// Verify
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.GreaterOrEqual(t, len(token), 32) // Base64 encoding may slightly increase the length
}

func TestGenerateOpaqueToken_InvalidLength(t *testing.T) {
	t.Parallel()
	// Setup
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	// Execute
	token, err := accessTokenService.GenerateOpaqueToken(0)

	// Verify
	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "invalid token length")
}

func TestCreateToken_NewToken(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	clientID := uuid.New()
	client := &models.Client{
		ID:          clientID,
		Name:        "Test Client",
		RedirectURI: "https://example.com/callback",
	}
	userID := uuid.New().String()
	scopes := "read write"
	tokenLength := 32

	// No existing token
	mockRepo.On("GetByUserAndClient", ctx, userID, clientID.String()).Return([]*cachemodels.AccessToken{}, nil)

	// Expect token creation
	mockRepo.On("Create", ctx, mock.AnythingOfType("*cachemodels.AccessToken")).Run(func(args mock.Arguments) {
		token := args.Get(1).(*cachemodels.AccessToken)
		assert.NotEmpty(t, token.Token)
		assert.Equal(t, scopes, token.Scopes)
		assert.Equal(t, clientID.String(), token.ClientID)
		assert.Equal(t, userID, token.UserID)
		assert.Equal(t, constants.TokenTypeBearer, token.TokenType)
		assert.Equal(t, client.RedirectURI, token.Audience)
		assert.Zero(t, token.ExpiresIn)
		assert.Zero(t, token.IssuedAt)
		assert.Zero(t, token.NotBefore)
	}).Return(nil)

	// Execute
	token, err := accessTokenService.CreateToken(ctx, client, userID, scopes, tokenLength)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, token)
	mockRepo.AssertExpectations(t)
}

func TestCreateToken_ExistingToken(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	clientID := uuid.New()
	client := &models.Client{
		ID:   clientID,
		Name: "Test Client",
	}
	userID := uuid.New().String()
	scopes := "read write"
	tokenLength := 32

	// Create an existing token
	existingToken := &cachemodels.AccessToken{
		Token:     "existing-token",
		Scopes:    scopes,
		ClientID:  clientID.String(),
		UserID:    userID,
		TokenType: constants.TokenTypeBearer,
		ExpiresIn: int(time.Now().Add(time.Hour).Unix()),
		IssuedAt:  int(time.Now().Unix()),
		NotBefore: int(time.Now().Unix()),
	}

	// Return the existing token
	mockRepo.On("GetByUserAndClient", ctx, userID, clientID.String()).Return([]*cachemodels.AccessToken{existingToken}, nil)

	// Execute
	token, err := accessTokenService.CreateToken(ctx, client, userID, scopes, tokenLength)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, existingToken, token)
	mockRepo.AssertExpectations(t)
}

func TestCreateToken_RepositoryError(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	clientID := uuid.New()
	client := &models.Client{
		ID:   clientID,
		Name: "Test Client",
	}
	userID := uuid.New().String()
	scopes := "read write"
	tokenLength := 32

	// Repository error on GetByUserAndClient
	mockRepo.On("GetByUserAndClient", ctx, userID, clientID.String()).Return([]*cachemodels.AccessToken{}, errors.New("repository error"))

	// Execute
	token, err := accessTokenService.CreateToken(ctx, client, userID, scopes, tokenLength)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to get existing access token")
	mockRepo.AssertExpectations(t)
}

func TestCreateToken_CreationError(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	clientID := uuid.New()
	client := &models.Client{
		ID:          clientID,
		Name:        "Test Client",
		RedirectURI: "https://example.com/callback",
	}
	userID := uuid.New().String()
	scopes := "read write"
	tokenLength := 32

	// No existing token
	mockRepo.On("GetByUserAndClient", ctx, userID, clientID.String()).Return([]*cachemodels.AccessToken{}, nil)

	// Error on creation
	mockRepo.On("Create", ctx, mock.AnythingOfType("*cachemodels.AccessToken")).Return(errors.New("creation error"))

	// Execute
	token, err := accessTokenService.CreateToken(ctx, client, userID, scopes, tokenLength)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to create access token")
	mockRepo.AssertExpectations(t)
}

func TestGetTokenForUserClient_Success(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()

	expectedToken := &cachemodels.AccessToken{
		Token:     "test-token",
		ClientID:  clientID,
		UserID:    userID,
		TokenType: constants.TokenTypeBearer,
	}

	mockRepo.On("GetByUserAndClient", ctx, userID, clientID).Return([]*cachemodels.AccessToken{expectedToken}, nil)

	// Execute
	token, err := accessTokenService.GetTokenForUserClient(ctx, clientID, userID)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, expectedToken, token)
	mockRepo.AssertExpectations(t)
}

func TestGetTokenForUserClient_NoToken(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()

	// No tokens found
	mockRepo.On("GetByUserAndClient", ctx, userID, clientID).Return([]*cachemodels.AccessToken{}, nil)

	// Execute
	token, err := accessTokenService.GetTokenForUserClient(ctx, clientID, userID)

	// Verify
	assert.NoError(t, err)
	assert.Nil(t, token)
	mockRepo.AssertExpectations(t)
}

func TestGetTokenForUserClient_MultipleTokens(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()

	// Multiple tokens found (this should not happen in practice)
	token1 := &cachemodels.AccessToken{Token: "token1", ClientID: clientID, UserID: userID}
	token2 := &cachemodels.AccessToken{Token: "token2", ClientID: clientID, UserID: userID}
	mockRepo.On("GetByUserAndClient", ctx, userID, clientID).Return([]*cachemodels.AccessToken{token1, token2}, nil)

	// Execute
	token, err := accessTokenService.GetTokenForUserClient(ctx, clientID, userID)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "multiple access tokens found")
	mockRepo.AssertExpectations(t)
}

func TestGetTokenForUserClient_RepositoryError(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()

	// Repository error
	mockRepo.On("GetByUserAndClient", ctx, userID, clientID).Return([]*cachemodels.AccessToken{}, errors.New("repository error"))

	// Execute
	token, err := accessTokenService.GetTokenForUserClient(ctx, clientID, userID)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to get access tokens")
	mockRepo.AssertExpectations(t)
}

func TestGetTokenDetails_Success(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	tokenValue := "test-token"
	expectedToken := &cachemodels.AccessToken{
		Token:     tokenValue,
		TokenType: constants.TokenTypeBearer,
	}

	mockRepo.On("GetByToken", ctx, tokenValue).Return(expectedToken, nil)

	// Execute
	token, err := accessTokenService.GetTokenDetails(ctx, tokenValue)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, expectedToken, token)
	mockRepo.AssertExpectations(t)
}

func TestGetTokenDetails_NotFound(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	tokenValue := "non-existent-token"

	mockRepo.On("GetByToken", ctx, tokenValue).Return(nil, errors.New("token not found"))

	// Execute
	token, err := accessTokenService.GetTokenDetails(ctx, tokenValue)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to get access token")
	mockRepo.AssertExpectations(t)
}

func TestRevokeToken_Success(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	token := &cachemodels.AccessToken{
		Token:     "token-to-revoke",
		TokenType: constants.TokenTypeBearer,
	}

	mockRepo.On("Update", ctx, token).Return(nil)

	// Execute
	err := accessTokenService.RevokeToken(ctx, token)

	// Verify
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestRevokeToken_Error(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAccessTokenRepository)
	accessTokenService := services.NewAccessTokenService(mockRepo)

	token := &cachemodels.AccessToken{
		Token:     "token-to-revoke",
		TokenType: constants.TokenTypeBearer,
	}

	mockRepo.On("Update", ctx, token).Return(errors.New("update error"))

	// Execute
	err := accessTokenService.RevokeToken(ctx, token)

	// Verify
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete access token")
	mockRepo.AssertExpectations(t)
}
