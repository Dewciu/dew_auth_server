package services_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuthorizationCodeRepository is a mock implementation of the IAuthorizationCodeRepository interface
type MockAuthorizationCodeRepository struct {
	mock.Mock
}

func (m *MockAuthorizationCodeRepository) Create(ctx context.Context, codeData *cachemodels.AuthorizationCode) error {
	args := m.Called(ctx, codeData)
	return args.Error(0)
}

func (m *MockAuthorizationCodeRepository) GetByCode(ctx context.Context, code string) (*cachemodels.AuthorizationCode, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cachemodels.AuthorizationCode), args.Error(1)
}

func TestGenerateCodeWithPKCE_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	clientID := uuid.New()
	client := &models.Client{
		ID:     clientID,
		Name:   "Test Client",
		Scopes: "read write",
	}
	userID := uuid.New().String()
	redirectURI := "https://example.com/callback"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	codeChallengeMethod := string(constants.SHA256Method)

	// Mock repository call
	mockRepo.On("Create", ctx, mock.AnythingOfType("*cachemodels.AuthorizationCode")).Run(func(args mock.Arguments) {
		authCode := args.Get(1).(*cachemodels.AuthorizationCode)
		assert.NotEmpty(t, authCode.Code)
		assert.Equal(t, userID, authCode.UserID)
		assert.Equal(t, clientID.String(), authCode.ClientID)
		assert.Equal(t, redirectURI, authCode.RedirectURI)
		assert.Equal(t, client.Scopes, authCode.Scopes)
		assert.Equal(t, codeChallenge, authCode.CodeChallenge)
		assert.Equal(t, codeChallengeMethod, authCode.CodeChallengeMethod)
	}).Return(nil)

	// Execute
	code, err := authCodeService.GenerateCodeWithPKCE(ctx, client, userID, redirectURI, codeChallenge, codeChallengeMethod)

	// Verify
	assert.NoError(t, err)
	assert.NotEmpty(t, code)
	mockRepo.AssertExpectations(t)
}

func TestGenerateCodeWithPKCE_RepositoryError(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	clientID := uuid.New()
	client := &models.Client{
		ID:     clientID,
		Name:   "Test Client",
		Scopes: "read write",
	}
	userID := uuid.New().String()
	redirectURI := "https://example.com/callback"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	codeChallengeMethod := string(constants.SHA256Method)

	// Mock repository error
	mockRepo.On("Create", ctx, mock.AnythingOfType("*cachemodels.AuthorizationCode")).Return(errors.New("repository error"))

	// Execute
	code, err := authCodeService.GenerateCodeWithPKCE(ctx, client, userID, redirectURI, codeChallenge, codeChallengeMethod)

	// Verify
	assert.Error(t, err)
	assert.Empty(t, code)
	mockRepo.AssertExpectations(t)
}

func TestValidateCode_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	authCode := "valid-auth-code"
	redirectURI := "https://example.com/callback"
	clientID := uuid.New().String()

	expectedAuthCode := &cachemodels.AuthorizationCode{
		Code:                authCode,
		UserID:              uuid.New().String(),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              "read write",
		CodeChallenge:       "code-challenge-value",
		CodeChallengeMethod: string(constants.SHA256Method),
	}

	// Mock repository call
	mockRepo.On("GetByCode", ctx, authCode).Return(expectedAuthCode, nil)

	// Execute
	result, err := authCodeService.ValidateCode(ctx, authCode, redirectURI, clientID)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, expectedAuthCode, result)
	mockRepo.AssertExpectations(t)
}

func TestValidateCode_EmptyCode(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	// Execute
	result, err := authCodeService.ValidateCode(ctx, "", "https://example.com/callback", uuid.New().String())

	// Verify
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.IsType(t, serviceerrors.InvalidAuthorizationCodeError{}, err)
	// Repository should not be called
	mockRepo.AssertNotCalled(t, "GetByCode")
}

func TestValidateCode_RepositoryError(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	authCode := "invalid-auth-code"
	redirectURI := "https://example.com/callback"
	clientID := uuid.New().String()

	// Mock repository error
	mockRepo.On("GetByCode", ctx, authCode).Return(nil, errors.New("repository error"))

	// Execute
	result, err := authCodeService.ValidateCode(ctx, authCode, redirectURI, clientID)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, result)
	mockRepo.AssertExpectations(t)
}

func TestValidateCode_RedirectURIMismatch(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	authCode := "valid-auth-code"
	storedRedirectURI := "https://example.com/original-callback"
	requestedRedirectURI := "https://example.com/different-callback"
	clientID := uuid.New().String()

	storedAuthCode := &cachemodels.AuthorizationCode{
		Code:                authCode,
		UserID:              uuid.New().String(),
		ClientID:            clientID,
		RedirectURI:         storedRedirectURI,
		Scopes:              "read write",
		CodeChallenge:       "code-challenge-value",
		CodeChallengeMethod: string(constants.SHA256Method),
	}

	// Mock repository call
	mockRepo.On("GetByCode", ctx, authCode).Return(storedAuthCode, nil)

	// Execute
	result, err := authCodeService.ValidateCode(ctx, authCode, requestedRedirectURI, clientID)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.IsType(t, serviceerrors.InvalidRedirectURIError{}, err)
	mockRepo.AssertExpectations(t)
}

func TestValidateCode_ClientIDMismatch(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	authCode := "valid-auth-code"
	redirectURI := "https://example.com/callback"
	storedClientID := uuid.New().String()
	requestedClientID := uuid.New().String() // Different client ID

	storedAuthCode := &cachemodels.AuthorizationCode{
		Code:                authCode,
		UserID:              uuid.New().String(),
		ClientID:            storedClientID,
		RedirectURI:         redirectURI,
		Scopes:              "read write",
		CodeChallenge:       "code-challenge-value",
		CodeChallengeMethod: string(constants.SHA256Method),
	}

	// Mock repository call
	mockRepo.On("GetByCode", ctx, authCode).Return(storedAuthCode, nil)

	// Execute
	result, err := authCodeService.ValidateCode(ctx, authCode, redirectURI, requestedClientID)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.IsType(t, serviceerrors.TokenClientMismatchError{}, err)
	mockRepo.AssertExpectations(t)
}

func TestValidatePKCE_S256Success(t *testing.T) {
	// Setup
	authCodeService := services.NewAuthorizationCodeService(nil) // Repository not needed for this test

	// Create a code verifier
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// Generate code challenge using SHA256
	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	// Execute
	err := authCodeService.ValidatePKCE(codeVerifier, codeChallenge, string(constants.SHA256Method))

	// Verify
	assert.NoError(t, err)
}

func TestValidatePKCE_PlainSuccess(t *testing.T) {
	// Setup
	authCodeService := services.NewAuthorizationCodeService(nil) // Repository not needed for this test

	// For plain method, code verifier is the same as code challenge
	codeVerifier := "plain-code-verifier"
	codeChallenge := codeVerifier

	// Execute
	err := authCodeService.ValidatePKCE(codeVerifier, codeChallenge, string(constants.PlainMethod))

	// Verify
	assert.NoError(t, err)
}

func TestValidatePKCE_S256Failure(t *testing.T) {
	// Setup
	authCodeService := services.NewAuthorizationCodeService(nil) // Repository not needed for this test

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	wrongCodeChallenge := "incorrect-challenge-value"

	// Execute
	err := authCodeService.ValidatePKCE(codeVerifier, wrongCodeChallenge, string(constants.SHA256Method))

	// Verify
	assert.Error(t, err)
	assert.IsType(t, serviceerrors.InvalidPKCEVerifierError{}, err)
}

func TestValidatePKCE_PlainFailure(t *testing.T) {
	// Setup
	authCodeService := services.NewAuthorizationCodeService(nil) // Repository not needed for this test

	codeVerifier := "plain-code-verifier"
	wrongCodeChallenge := "different-challenge-value"

	// Execute
	err := authCodeService.ValidatePKCE(codeVerifier, wrongCodeChallenge, string(constants.PlainMethod))

	// Verify
	assert.Error(t, err)
	assert.IsType(t, serviceerrors.InvalidPKCEVerifierError{}, err)
}

func TestValidatePKCE_UnsupportedMethod(t *testing.T) {
	// Setup
	authCodeService := services.NewAuthorizationCodeService(nil) // Repository not needed for this test

	codeVerifier := "code-verifier"
	codeChallenge := "code-challenge"
	unsupportedMethod := "unsupported-method"

	// Execute
	err := authCodeService.ValidatePKCE(codeVerifier, codeChallenge, unsupportedMethod)

	// Verify
	assert.Error(t, err)
	assert.IsType(t, serviceerrors.UnsupportedPKCEMethodError{}, err)
}

func TestValidatePKCE_EmptyVerifier(t *testing.T) {
	// Setup
	authCodeService := services.NewAuthorizationCodeService(nil) // Repository not needed for this test

	// Execute
	err := authCodeService.ValidatePKCE("", "challenge", string(constants.SHA256Method))

	// Verify
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PKCE code verifier is required")
}

func TestGenerateCodeWithPKCE_NullParameters(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	// Execute with nil client
	code, err := authCodeService.GenerateCodeWithPKCE(ctx, nil, "user-id", "https://example.com", "challenge", "S256")

	// Verify
	assert.Error(t, err)
	assert.Empty(t, code)
	assert.Contains(t, err.Error(), "client cannot be nil")

	// Execute with empty user ID
	clientID := uuid.New()
	client := &models.Client{
		ID:     clientID,
		Name:   "Test Client",
		Scopes: "read write",
	}
	code, err = authCodeService.GenerateCodeWithPKCE(ctx, client, "", "https://example.com", "challenge", "S256")

	// Verify
	assert.Error(t, err)
	assert.Empty(t, code)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestGenerateCodeWithPKCE_InvalidCodeChallenge(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	clientID := uuid.New()
	client := &models.Client{
		ID:     clientID,
		Name:   "Test Client",
		Scopes: "read write",
	}
	userID := uuid.New().String()
	redirectURI := "https://example.com/callback"

	// Test with empty code challenge
	code, err := authCodeService.GenerateCodeWithPKCE(ctx, client, userID, redirectURI, "", string(constants.SHA256Method))

	// Verify
	assert.Error(t, err)
	assert.Empty(t, code)
	assert.Contains(t, err.Error(), "code challenge is required")

	// Test with empty code challenge method
	code, err = authCodeService.GenerateCodeWithPKCE(ctx, client, userID, redirectURI, "challenge", "")

	// Verify
	assert.Error(t, err)
	assert.Empty(t, code)
	assert.Contains(t, err.Error(), "code challenge method is required")
}

func TestValidateCode_NilCode(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockAuthorizationCodeRepository)
	authCodeService := services.NewAuthorizationCodeService(mockRepo)

	// Mock repository to return nil without error (unexpected case)
	mockRepo.On("GetByCode", ctx, "auth-code").Return(nil, nil)

	// Execute
	result, err := authCodeService.ValidateCode(ctx, "auth-code", "https://example.com", uuid.New().String())

	// Verify
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid or expired")
	mockRepo.AssertExpectations(t)
}
