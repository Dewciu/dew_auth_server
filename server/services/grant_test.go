package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock services
type MockAccessTokenService struct {
	mock.Mock
}

func (m *MockAccessTokenService) GenerateOpaqueToken(length int) (string, error) {
	args := m.Called(length)
	return args.String(0), args.Error(1)
}

func (m *MockAccessTokenService) CreateToken(ctx context.Context, client *models.Client, userID string, scope string, tokenLength int) (*cachemodels.AccessToken, error) {
	args := m.Called(ctx, client, userID, scope, tokenLength)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cachemodels.AccessToken), args.Error(1)
}

func (m *MockAccessTokenService) GetTokenForUserClient(ctx context.Context, clientID string, userID string) (*cachemodels.AccessToken, error) {
	args := m.Called(ctx, clientID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cachemodels.AccessToken), args.Error(1)
}

func (m *MockAccessTokenService) GetTokenDetails(ctx context.Context, token string) (*cachemodels.AccessToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cachemodels.AccessToken), args.Error(1)
}

func (m *MockAccessTokenService) RevokeToken(ctx context.Context, token *cachemodels.AccessToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

type MockRefreshTokenService struct {
	mock.Mock
}

func (m *MockRefreshTokenService) GenerateOpaqueToken(length int) (string, error) {
	args := m.Called(length)
	return args.String(0), args.Error(1)
}

func (m *MockRefreshTokenService) CreateRefreshToken(ctx context.Context, clientID string, userID string, scope string, tokenLength int) (string, error) {
	args := m.Called(ctx, clientID, userID, scope, tokenLength)
	return args.String(0), args.Error(1)
}

func (m *MockRefreshTokenService) GetTokenDetails(ctx context.Context, token string) (*cachemodels.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cachemodels.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenService) RevokeToken(ctx context.Context, token *cachemodels.RefreshToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// Test ObtainByAuthCode
func TestObtainByAuthCode_Success(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	userID := "test-user-id"
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "authorization_code",
		ResponseTypes: "token",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Auth code details
	authCode := &cachemodels.AuthorizationCode{
		Code:                "test-auth-code",
		UserID:              userID,
		ClientID:            clientID.String(),
		RedirectURI:         "https://example.com/callback",
		Scopes:              "read write",
		CodeChallenge:       "test-code-challenge",
		CodeChallengeMethod: "S256",
	}

	// Access token
	accessToken := &cachemodels.AccessToken{
		Token:     "test-access-token",
		ClientID:  clientID.String(),
		UserID:    userID,
		Scopes:    "read write",
		TokenType: constants.TokenTypeBearer,
	}

	// Test input
	input := inputs.AuthorizationCodeGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "authorization_code",
		},
		RedirectURI:  "https://example.com/callback",
		Code:         "test-auth-code",
		CodeVerifier: "test-code-verifier",
	}

	// Set up expectations
	mockAuthCodeService.On("ValidateCode", ctx, input.Code, input.RedirectURI, clientID.String()).Return(authCode, nil)
	mockAuthCodeService.On("ValidatePKCE", input.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod).Return(nil)
	mockAccessTokenService.On("CreateToken", ctx, client, userID, authCode.Scopes, 64).Return(accessToken, nil)
	mockAccessTokenService.On("GetTokenForUserClient", ctx, client.ID.String(), userID).Return(nil, nil)
	mockRefreshTokenService.On("CreateRefreshToken", ctx, clientID.String(), userID, authCode.Scopes, 32).Return("test-refresh-token", nil)

	// Call the method
	output, err := grantService.ObtainByAuthCode(ctx, input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, accessToken.Token, output.AccessToken.Token)
	assert.Equal(t, "test-refresh-token", output.RefreshToken)

	// Verify mocks
	mockAuthCodeService.AssertExpectations(t)
	mockAccessTokenService.AssertExpectations(t)
	mockRefreshTokenService.AssertExpectations(t)
}

func TestObtainByAuthCode_UnsupportedGrantType(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "refresh_token", // Doesn't support authorization_code
		ResponseTypes: "token",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Test input
	input := inputs.AuthorizationCodeGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "authorization_code",
		},
		RedirectURI:  "https://example.com/callback",
		Code:         "test-auth-code",
		CodeVerifier: "test-code-verifier",
	}

	// Call the method
	output, err := grantService.ObtainByAuthCode(ctx, input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.UnsupportedGrantTypeError{}, err)
}

func TestObtainByAuthCode_UnsupportedResponseType(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "authorization_code",
		ResponseTypes: "code", // Doesn't support token
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Test input
	input := inputs.AuthorizationCodeGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "authorization_code",
		},
		RedirectURI:  "https://example.com/callback",
		Code:         "test-auth-code",
		CodeVerifier: "test-code-verifier",
	}

	// Call the method
	output, err := grantService.ObtainByAuthCode(ctx, input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.UnsupportedResponseTypeError{}, err)
}

func TestObtainByAuthCode_InvalidCode(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "authorization_code",
		ResponseTypes: "token",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Test input
	input := inputs.AuthorizationCodeGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "authorization_code",
		},
		RedirectURI:  "https://example.com/callback",
		Code:         "invalid-code",
		CodeVerifier: "test-code-verifier",
	}

	// Set up expectations
	mockAuthCodeService.On("ValidateCode", ctx, input.Code, input.RedirectURI, clientID.String()).
		Return(nil, serviceerrors.NewInvalidAuthorizationCodeError("invalid-code"))

	// Call the method
	output, err := grantService.ObtainByAuthCode(ctx, input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.InvalidAuthorizationCodeError{}, err)

	// Verify mocks
	mockAuthCodeService.AssertExpectations(t)
}

func TestObtainByAuthCode_PKCEVerificationFails(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	userID := "test-user-id"
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "authorization_code",
		ResponseTypes: "token",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Auth code details
	authCode := &cachemodels.AuthorizationCode{
		Code:                "test-auth-code",
		UserID:              userID,
		ClientID:            clientID.String(),
		RedirectURI:         "https://example.com/callback",
		Scopes:              "read write",
		CodeChallenge:       "expected-challenge",
		CodeChallengeMethod: "S256",
	}

	// Test input
	input := inputs.AuthorizationCodeGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "authorization_code",
		},
		RedirectURI:  "https://example.com/callback",
		Code:         "test-auth-code",
		CodeVerifier: "invalid-verifier",
	}

	// Set up expectations
	mockAuthCodeService.On("ValidateCode", ctx, input.Code, input.RedirectURI, clientID.String()).Return(authCode, nil)
	mockAuthCodeService.On("ValidatePKCE", input.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod).
		Return(serviceerrors.NewInvalidPKCEVerifierError("code verifier does not match challenge"))

	// Call the method
	output, err := grantService.ObtainByAuthCode(ctx, input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.InvalidPKCEVerifierError{}, err)

	// Verify mocks
	mockAuthCodeService.AssertExpectations(t)
}

func TestObtainByAuthCode_TokenCreationFails(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	userID := "test-user-id"
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "authorization_code",
		ResponseTypes: "token",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Auth code details
	authCode := &cachemodels.AuthorizationCode{
		Code:                "test-auth-code",
		UserID:              userID,
		ClientID:            clientID.String(),
		RedirectURI:         "https://example.com/callback",
		Scopes:              "read write",
		CodeChallenge:       "test-code-challenge",
		CodeChallengeMethod: "S256",
	}

	// Test input
	input := inputs.AuthorizationCodeGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "authorization_code",
		},
		RedirectURI:  "https://example.com/callback",
		Code:         "test-auth-code",
		CodeVerifier: "test-code-verifier",
	}

	// Set up expectations
	mockAuthCodeService.On("ValidateCode", ctx, input.Code, input.RedirectURI, clientID.String()).Return(authCode, nil)
	mockAuthCodeService.On("ValidatePKCE", input.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod).Return(nil)
	mockAccessTokenService.On("GetTokenForUserClient", ctx, client.ID.String(), userID).Return(nil, nil)
	mockAccessTokenService.On("CreateToken", ctx, client, userID, authCode.Scopes, 64).
		Return(nil, errors.New("token creation failed"))

	// Call the method
	output, err := grantService.ObtainByAuthCode(ctx, input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "token creation failed")

	// Verify mocks
	mockAuthCodeService.AssertExpectations(t)
	mockAccessTokenService.AssertExpectations(t)
}

// Test ObtainByRefreshToken
func TestObtainByRefreshToken_Success(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	userID := "test-user-id"
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "refresh_token",
		ResponseTypes: "token",
		Scopes:        "read write",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Refresh token details
	refreshToken := &cachemodels.RefreshToken{
		Token:    "test-refresh-token",
		ClientID: clientID.String(),
		UserID:   userID,
		Scopes:   "read write",
	}

	// Access token
	accessToken := &cachemodels.AccessToken{
		Token:     "test-access-token",
		ClientID:  clientID.String(),
		UserID:    userID,
		Scopes:    "read write",
		TokenType: constants.TokenTypeBearer,
	}

	// Test input
	input := inputs.RefreshTokenGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "refresh_token",
		},
		RefreshToken: "test-refresh-token",
	}

	// Set up expectations
	mockRefreshTokenService.On("GetTokenDetails", ctx, input.RefreshToken).Return(refreshToken, nil)
	mockAccessTokenService.On("CreateToken", ctx, client, userID, refreshToken.Scopes, 64).Return(accessToken, nil)
	// This test case creates a new refresh token
	mockRefreshTokenService.On("CreateRefreshToken", ctx, clientID.String(), userID, refreshToken.Scopes, 32).Return("new-refresh-token", nil)
	mockRefreshTokenService.On("RevokeToken", ctx, refreshToken).Return(nil)

	// Call the method
	output, err := grantService.ObtainByRefreshToken(ctx, input, true)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, accessToken.Token, output.AccessToken.Token)
	assert.Equal(t, "new-refresh-token", output.RefreshToken)

	// Verify mocks
	mockRefreshTokenService.AssertExpectations(t)
	mockAccessTokenService.AssertExpectations(t)
}

func TestObtainByRefreshToken_WithoutNewRefreshToken(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	userID := "test-user-id"
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "refresh_token",
		ResponseTypes: "token",
		Scopes:        "read write",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Refresh token details
	refreshToken := &cachemodels.RefreshToken{
		Token:    "test-refresh-token",
		ClientID: clientID.String(),
		UserID:   userID,
		Scopes:   "read write",
	}

	// Access token
	accessToken := &cachemodels.AccessToken{
		Token:     "test-access-token",
		ClientID:  clientID.String(),
		UserID:    userID,
		Scopes:    "read write",
		TokenType: constants.TokenTypeBearer,
	}

	// Test input
	input := inputs.RefreshTokenGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "refresh_token",
		},
		RefreshToken: "test-refresh-token",
	}

	// Set up expectations
	mockRefreshTokenService.On("GetTokenDetails", ctx, input.RefreshToken).Return(refreshToken, nil)
	mockAccessTokenService.On("CreateToken", ctx, client, userID, refreshToken.Scopes, 64).Return(accessToken, nil)
	// Not expecting CreateRefreshToken to be called in this case

	// Call the method - not creating a new refresh token
	output, err := grantService.ObtainByRefreshToken(ctx, input, false)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, accessToken.Token, output.AccessToken.Token)
	assert.Equal(t, "test-refresh-token", output.RefreshToken) // Should return the same refresh token

	// Verify mocks
	mockRefreshTokenService.AssertExpectations(t)
	mockAccessTokenService.AssertExpectations(t)
}

func TestObtainByRefreshToken_UnsupportedGrantType(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "authorization_code", // Doesn't support refresh_token
		ResponseTypes: "token",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Test input
	input := inputs.RefreshTokenGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "refresh_token",
		},
		RefreshToken: "test-refresh-token",
	}

	// Call the method
	output, err := grantService.ObtainByRefreshToken(ctx, input, true)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.UnsupportedGrantTypeError{}, err)
}

func TestObtainByRefreshToken_InvalidToken(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "refresh_token",
		ResponseTypes: "token",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Test input
	input := inputs.RefreshTokenGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "refresh_token",
		},
		RefreshToken: "invalid-token",
	}

	// Set up expectations
	mockRefreshTokenService.On("GetTokenDetails", ctx, input.RefreshToken).
		Return(nil, serviceerrors.NewTokenNotFoundError("invalid-token"))

	// Call the method
	output, err := grantService.ObtainByRefreshToken(ctx, input, true)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.TokenNotFoundError{}, err)

	// Verify mocks
	mockRefreshTokenService.AssertExpectations(t)
}

func TestObtainByRefreshToken_ClientMismatch(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	otherClientID := uuid.New() // Different client ID
	userID := "test-user-id"
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "refresh_token",
		ResponseTypes: "token",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Refresh token details that belong to a different client
	refreshToken := &cachemodels.RefreshToken{
		Token:    "test-refresh-token",
		ClientID: otherClientID.String(), // Different client
		UserID:   userID,
		Scopes:   "read write",
	}

	// Test input
	input := inputs.RefreshTokenGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "refresh_token",
		},
		RefreshToken: "test-refresh-token",
	}

	// Set up expectations
	mockRefreshTokenService.On("GetTokenDetails", ctx, input.RefreshToken).Return(refreshToken, nil)

	// Call the method
	output, err := grantService.ObtainByRefreshToken(ctx, input, true)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.ClientAuthorizationError{}, err)

	// Verify mocks
	mockRefreshTokenService.AssertExpectations(t)
}

func TestObtainByRefreshToken_InvalidScope(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	userID := "test-user-id"
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "refresh_token",
		ResponseTypes: "token",
		Scopes:        "read write delete", // Has "delete" scope that's not in the token
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Refresh token with limited scopes
	refreshToken := &cachemodels.RefreshToken{
		Token:    "test-refresh-token",
		ClientID: clientID.String(),
		UserID:   userID,
		Scopes:   "read", // Only has "read" scope, not "write delete"
	}

	// Test input
	input := inputs.RefreshTokenGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "refresh_token",
		},
		RefreshToken: "test-refresh-token",
	}

	// Set up expectations
	mockRefreshTokenService.On("GetTokenDetails", ctx, input.RefreshToken).Return(refreshToken, nil)

	// Call the method
	output, err := grantService.ObtainByRefreshToken(ctx, input, true)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.InvalidScopeError{}, err)

	// Verify mocks
	mockRefreshTokenService.AssertExpectations(t)
}

func TestObtainByRefreshToken_TokenCreationFails(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	userID := "test-user-id"
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "refresh_token",
		ResponseTypes: "token",
		Scopes:        "read write",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Refresh token
	refreshToken := &cachemodels.RefreshToken{
		Token:    "test-refresh-token",
		ClientID: clientID.String(),
		UserID:   userID,
		Scopes:   "read write",
	}

	// Test input
	input := inputs.RefreshTokenGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "refresh_token",
		},
		RefreshToken: "test-refresh-token",
	}

	// Set up expectations
	mockRefreshTokenService.On("GetTokenDetails", ctx, input.RefreshToken).Return(refreshToken, nil)
	mockAccessTokenService.On("CreateToken", ctx, client, userID, refreshToken.Scopes, 64).
		Return(nil, errors.New("token creation failed"))

	// Call the method
	output, err := grantService.ObtainByRefreshToken(ctx, input, true)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "token creation failed")

	// Verify mocks
	mockRefreshTokenService.AssertExpectations(t)
	mockAccessTokenService.AssertExpectations(t)
}

// Test ObtainByClientCredentials
func TestObtainByClientCredentials_Success(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "client_credentials",
		ResponseTypes: "token",
		Scopes:        "read write",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Access token
	accessToken := &cachemodels.AccessToken{
		Token:     "test-access-token",
		ClientID:  clientID.String(),
		UserID:    clientID.String(), // UserID is the clientID for client credentials
		Scopes:    "read write",
		TokenType: constants.TokenTypeBearer,
	}

	// Test input
	input := inputs.ClientCredentialsGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "client_credentials",
		},
		Scopes: "read",
	}

	// Set up expectations
	mockAccessTokenService.On("GetTokenForUserClient", ctx, client.ID.String(), client.ID.String()).Return(nil, nil)
	mockAccessTokenService.On("CreateToken", ctx, client, clientID.String(), input.Scopes, 64).Return(accessToken, nil)

	// Call the method
	output, err := grantService.ObtainByClientCredentials(ctx, input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, accessToken.Token, output.AccessToken.Token)
	assert.Empty(t, output.RefreshToken) // No refresh token for client credentials

	// Verify mocks
	mockAccessTokenService.AssertExpectations(t)
}

func TestObtainByClientCredentials_WithRequestedScopes(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "client_credentials",
		ResponseTypes: "token",
		Scopes:        "read write delete", // Client has all these scopes
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Access token
	accessToken := &cachemodels.AccessToken{
		Token:     "test-access-token",
		ClientID:  clientID.String(),
		UserID:    clientID.String(),
		Scopes:    "read", // Requested only read scope
		TokenType: constants.TokenTypeBearer,
	}

	// Test input - requesting only a subset of scopes
	input := inputs.ClientCredentialsGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "client_credentials",
		},
		Scopes: "read", // Only requesting read scope
	}

	// Set up expectations
	mockAccessTokenService.On("GetTokenForUserClient", ctx, client.ID.String(), client.ID.String()).Return(nil, nil)
	mockAccessTokenService.On("CreateToken", ctx, client, clientID.String(), "read", 64).Return(accessToken, nil)

	// Call the method
	output, err := grantService.ObtainByClientCredentials(ctx, input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, accessToken.Token, output.AccessToken.Token)

	// Verify mocks
	mockAccessTokenService.AssertExpectations(t)
}

func TestObtainByClientCredentials_UnsupportedGrantType(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "authorization_code refresh_token", // Doesn't support client_credentials
		ResponseTypes: "token",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Test input
	input := inputs.ClientCredentialsGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "client_credentials",
		},
	}

	// Call the method
	output, err := grantService.ObtainByClientCredentials(ctx, input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.UnsupportedGrantTypeError{}, err)
}

func TestObtainByClientCredentials_InvalidScope(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "client_credentials",
		ResponseTypes: "token",
		Scopes:        "read write", // Client only has read and write
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Test input - requesting unauthorized scope
	input := inputs.ClientCredentialsGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "client_credentials",
		},
		Scopes: "read write delete", // Requesting delete which client doesn't have
	}

	// Call the method
	output, err := grantService.ObtainByClientCredentials(ctx, input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.InvalidScopeError{}, err)
}

func TestObtainByClientCredentials_TokenCreationFails(t *testing.T) {
	t.Parallel()
	// Setup mocks
	mockAccessTokenService := new(MockAccessTokenService)
	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockRefreshTokenService := new(MockRefreshTokenService)

	// Create the service to test
	grantService := services.NewGrantService(
		mockAccessTokenService,
		mockClientService,
		mockAuthCodeService,
		mockRefreshTokenService,
	)

	// Test data
	clientID := uuid.New()
	ctx := context.Background()
	client := &models.Client{
		ID:            clientID,
		GrantTypes:    "client_credentials",
		ResponseTypes: "token",
		Scopes:        "read write",
	}

	// Add client to context
	ctx = appcontext.WithClient(ctx, client)

	// Test input
	input := inputs.ClientCredentialsGrantInput{
		AccessTokenInput: inputs.AccessTokenInput{
			GrantType: "client_credentials",
		},
		Scopes: "read write",
	}

	// Set up expectations
	mockAccessTokenService.On("GetTokenForUserClient", ctx, client.ID.String(), client.ID.String()).Return(nil, nil)
	mockAccessTokenService.On("CreateToken", ctx, client, clientID.String(), client.Scopes, 64).
		Return(nil, errors.New("token creation failed"))

	// Call the method
	output, err := grantService.ObtainByClientCredentials(ctx, input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "token creation failed")

	// Verify mocks
	mockAccessTokenService.AssertExpectations(t)
}
