package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClientService is a mock implementation of the IClientService interface
type MockClientService struct {
	mock.Mock
}

func (m *MockClientService) VerifyClient(ctx context.Context, clientID string, clientSecret string) (*models.Client, error) {
	args := m.Called(ctx, clientID, clientSecret)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientService) CheckIfClientExistsByName(ctx context.Context, clientName string) (*models.Client, error) {
	args := m.Called(ctx, clientName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientService) CheckIfClientExistsByID(ctx context.Context, clientID string) (*models.Client, error) {
	args := m.Called(ctx, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientService) RegisterClient(ctx context.Context, input inputs.IClientRegisterInput) (outputs.IClientRegisterOutput, error) {
	args := m.Called(ctx, input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(outputs.IClientRegisterOutput), args.Error(1)
}

// MockAuthCodeService is a mock implementation of the IAuthorizationCodeService interface
type MockAuthCodeService struct {
	mock.Mock
}

func (m *MockAuthCodeService) GenerateCodeWithPKCE(
	ctx context.Context,
	client *models.Client,
	userID string,
	redirectURI string,
	codeChallenge string,
	codeChallengeMethod string,
) (string, error) {
	args := m.Called(ctx, client, userID, redirectURI, codeChallenge, codeChallengeMethod)
	return args.String(0), args.Error(1)
}

func (m *MockAuthCodeService) ValidateCode(
	ctx context.Context,
	code string,
	redirectUri string,
	clientID string,
) (*cachemodels.AuthorizationCode, error) {
	args := m.Called(ctx, code, redirectUri, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cachemodels.AuthorizationCode), args.Error(1)
}

func (m *MockAuthCodeService) ValidatePKCE(
	codeVerifier,
	codeChallenge,
	codeChallengeMethod string,
) error {
	args := m.Called(codeVerifier, codeChallenge, codeChallengeMethod)
	return args.Error(0)
}

// MockUserService is a mock implementation of the IUserService interface
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) RegisterUser(ctx context.Context, userInput *inputs.UserRegisterInput) error {
	args := m.Called(ctx, userInput)
	return args.Error(0)
}

func (m *MockUserService) LoginUser(ctx context.Context, userLoginInput inputs.UserLoginInput) (*models.User, error) {
	args := m.Called(ctx, userLoginInput)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// MockAuthorizationInput is a mock implementation of the IAuthorizationInput interface
type MockAuthorizationInput struct {
	mock.Mock
}

func (m *MockAuthorizationInput) GetClientID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthorizationInput) GetRedirectURI() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthorizationInput) GetResponseType() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthorizationInput) GetScope() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthorizationInput) GetState() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthorizationInput) GetCodeChallenge() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthorizationInput) GetCodeChallengeMethod() string {
	args := m.Called()
	return args.String(0)
}

func createContextWithUserID(userID string) context.Context {
	return appcontext.WithUserID(context.Background(), userID)
}

func TestAuthorizeClient_Success(t *testing.T) {
	t.Parallel()
	// Setup
	userID := uuid.New().String()
	ctx := createContextWithUserID(userID)

	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockUserService := new(MockUserService)

	authService := services.NewAuthorizationService(
		mockClientService,
		mockAuthCodeService,
		mockUserService,
	)

	input := new(MockAuthorizationInput)
	clientID := uuid.New().String()
	redirectURI := "https://example.com/callback"
	// responseType := "code"
	// scope := "read write"
	state := "xyz123"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	codeChallengeMethod := string(constants.SHA256Method)

	input.On("GetClientID").Return(clientID)
	input.On("GetRedirectURI").Return(redirectURI)
	// input.On("GetResponseType").Return(responseType)
	// input.On("GetScope").Return(scope)
	input.On("GetState").Return(state)
	input.On("GetCodeChallenge").Return(codeChallenge)
	input.On("GetCodeChallengeMethod").Return(codeChallengeMethod)

	// Client exists
	client := &models.Client{
		ID:            uuid.MustParse(clientID),
		Name:          "Test Client",
		RedirectURI:   redirectURI,
		ResponseTypes: string(constants.TokenResponseType),
	}
	mockClientService.On("CheckIfClientExistsByID", ctx, clientID).Return(client, nil)

	// Auth code generation succeeds
	expectedAuthCode := "test-auth-code-123"
	mockAuthCodeService.On("GenerateCodeWithPKCE",
		ctx, client, userID, redirectURI, codeChallenge, codeChallengeMethod).
		Return(expectedAuthCode, nil)

	// Execute
	output, err := authService.AuthorizeClient(ctx, input)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, expectedAuthCode, output.GetCode())
	assert.Equal(t, state, output.GetState())

	mockClientService.AssertExpectations(t)
	mockAuthCodeService.AssertExpectations(t)
	mockUserService.AssertExpectations(t)
	input.AssertExpectations(t)
}

func TestAuthorizeClient_ClientNotFound(t *testing.T) {
	t.Parallel()
	// Setup
	userID := uuid.New().String()
	ctx := createContextWithUserID(userID)

	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockUserService := new(MockUserService)

	authService := services.NewAuthorizationService(
		mockClientService,
		mockAuthCodeService,
		mockUserService,
	)

	input := new(MockAuthorizationInput)
	clientID := "non-existent-client"

	input.On("GetClientID").Return(clientID)

	// Client does not exist
	mockClientService.On("CheckIfClientExistsByID", ctx, clientID).
		Return(nil, serviceerrors.NewClientNotFoundError(clientID))

	// Execute
	output, err := authService.AuthorizeClient(ctx, input)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.ClientNotFoundError{}, err)

	mockClientService.AssertExpectations(t)
	mockAuthCodeService.AssertNotCalled(t, "GenerateCodeWithPKCE")
	input.AssertExpectations(t)
}

func TestAuthorizeClient_UnsupportedResponseType(t *testing.T) {
	t.Parallel()
	// Setup
	userID := uuid.New().String()
	ctx := createContextWithUserID(userID)

	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockUserService := new(MockUserService)

	authService := services.NewAuthorizationService(
		mockClientService,
		mockAuthCodeService,
		mockUserService,
	)

	input := new(MockAuthorizationInput)
	clientID := uuid.New().String()
	redirectURI := "https://example.com/callback"

	input.On("GetClientID").Return(clientID)

	// Client exists but doesn't support the token response type
	client := &models.Client{
		ID:            uuid.MustParse(clientID),
		Name:          "Test Client",
		RedirectURI:   redirectURI,
		ResponseTypes: "other-response-type", // Doesn't include token
	}
	mockClientService.On("CheckIfClientExistsByID", ctx, clientID).Return(client, nil)

	// Execute
	output, err := authService.AuthorizeClient(ctx, input)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.UnsupportedResponseTypeError{}, err)

	mockClientService.AssertExpectations(t)
	mockAuthCodeService.AssertNotCalled(t, "GenerateCodeWithPKCE")
	input.AssertExpectations(t)
}

func TestAuthorizeClient_InvalidRedirectURI(t *testing.T) {
	t.Parallel()
	// Setup
	userID := uuid.New().String()
	ctx := createContextWithUserID(userID)

	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockUserService := new(MockUserService)

	authService := services.NewAuthorizationService(
		mockClientService,
		mockAuthCodeService,
		mockUserService,
	)

	input := new(MockAuthorizationInput)
	clientID := uuid.New().String()
	redirectURI := "https://attacker.com/callback" // Different domain

	input.On("GetClientID").Return(clientID)
	input.On("GetRedirectURI").Return(redirectURI)

	// Client exists with a different redirect URI
	client := &models.Client{
		ID:            uuid.MustParse(clientID),
		Name:          "Test Client",
		RedirectURI:   "https://example.com/callback", // Original URI
		ResponseTypes: string(constants.TokenResponseType),
	}
	mockClientService.On("CheckIfClientExistsByID", ctx, clientID).Return(client, nil)

	// Execute
	output, err := authService.AuthorizeClient(ctx, input)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.IsType(t, serviceerrors.InvalidRedirectURIForClientError{}, err)

	mockClientService.AssertExpectations(t)
	mockAuthCodeService.AssertNotCalled(t, "GenerateCodeWithPKCE")
	input.AssertExpectations(t)
}

func TestAuthorizeClient_CodeGenerationError(t *testing.T) {
	t.Parallel()
	// Setup
	userID := uuid.New().String()
	ctx := createContextWithUserID(userID)

	mockClientService := new(MockClientService)
	mockAuthCodeService := new(MockAuthCodeService)
	mockUserService := new(MockUserService)

	authService := services.NewAuthorizationService(
		mockClientService,
		mockAuthCodeService,
		mockUserService,
	)

	input := new(MockAuthorizationInput)
	clientID := uuid.New().String()
	redirectURI := "https://example.com/callback"
	// responseType := "code"
	// scope := "read write"
	// state := "xyz123"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	codeChallengeMethod := string(constants.SHA256Method)

	input.On("GetClientID").Return(clientID)
	input.On("GetRedirectURI").Return(redirectURI)
	// input.On("GetResponseType").Return(responseType)
	// input.On("GetScope").Return(scope)
	// input.On("GetState").Return(state)
	input.On("GetCodeChallenge").Return(codeChallenge)
	input.On("GetCodeChallengeMethod").Return(codeChallengeMethod)

	// Client exists
	client := &models.Client{
		ID:            uuid.MustParse(clientID),
		Name:          "Test Client",
		RedirectURI:   redirectURI,
		ResponseTypes: string(constants.TokenResponseType),
	}
	mockClientService.On("CheckIfClientExistsByID", ctx, clientID).Return(client, nil)

	// Auth code generation fails
	generationError := errors.New("code generation failed")
	mockAuthCodeService.On("GenerateCodeWithPKCE",
		ctx, client, userID, redirectURI, codeChallenge, codeChallengeMethod).
		Return("", generationError)

	// Execute
	output, err := authService.AuthorizeClient(ctx, input)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "failed to generate authorization code")

	mockClientService.AssertExpectations(t)
	mockAuthCodeService.AssertExpectations(t)
	mockUserService.AssertExpectations(t)
	input.AssertExpectations(t)
}
