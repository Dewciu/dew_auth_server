package controllers_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ing-bank/ginerr/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuthorizationService mocks the IAuthorizationService interface
type MockAuthorizationService struct {
	mock.Mock
}

func (m *MockAuthorizationService) AuthorizeClient(ctx context.Context, input inputs.IAuthorizationInput) (outputs.IAuthorizeOutput, error) {
	args := m.Called(ctx, input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(outputs.IAuthorizeOutput), args.Error(1)
}

// MockAuthorizeOutput implements IAuthorizeOutput for testing
type MockAuthorizeOutput struct {
	Code  string
	State string
}

func (o *MockAuthorizeOutput) GetCode() string {
	return o.Code
}

func (o *MockAuthorizeOutput) GetState() string {
	return o.State
}

func setupAuthorizationRouter(
	authService *MockAuthorizationService,
	consentService *MockConsentService,
	clientService *MockClientService,
	consentEndpoint string,
) (*gin.Engine, *controllers.AuthorizationController) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Setup session
	store := cookie.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("test-session", store))

	// Create controller
	controller := controllers.NewAuthorizationController(
		authService,
		consentService,
		clientService,
		consentEndpoint,
	)

	ginerr.RegisterErrorHandler(oautherrors.OAuthInputValidationErrorHandler)

	// Register route
	router.GET("/oauth2/authorize", func(c *gin.Context) {
		// Middleware to set user_id in context
		userID := uuid.New().String()
		c.Request = c.Request.WithContext(appcontext.WithUserID(c.Request.Context(), userID))
		controller.Authorize(c)
	})

	return router, &controller
}

func TestAuthorizeHandler_Success(t *testing.T) {
	t.Parallel()
	// Setup
	mockAuthService := new(MockAuthorizationService)
	mockConsentService := new(MockConsentService)
	mockClientService := new(MockClientService)
	consentEndpoint := "/oauth2/consent"

	router, _ := setupAuthorizationRouter(
		mockAuthService,
		mockConsentService,
		mockClientService,
		consentEndpoint,
	)

	// Create request with all required query parameters
	clientID := uuid.New().String()
	state := "xyz123"

	req, _ := http.NewRequest(http.MethodGet, "/oauth2/authorize"+
		"?client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&response_type=code"+
		"&scope=read"+
		"&state="+state+
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"+
		"&code_challenge_method=S256", nil)

	resp := httptest.NewRecorder()

	// Mock client service expectations
	clientUUID, _ := uuid.Parse(clientID)
	mockClient := &models.Client{
		ID:            clientUUID,
		ResponseTypes: "token",
		RedirectURI:   "https://example.com/callback",
	}

	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).Return(mockClient, nil)

	// Mock consent service expectations - consent exists
	mockConsentService.On("ConsentForClientAndUserExists", mock.Anything, clientID, mock.Anything).Return(true, nil)

	// Mock authorization service expectations
	mockOutput := &MockAuthorizeOutput{
		Code:  "auth_code_123",
		State: state,
	}

	mockAuthService.On("AuthorizeClient", mock.Anything, mock.Anything).Return(mockOutput, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusFound, resp.Code) // 302 Found for redirect
	assert.Equal(t, "https://example.com/callback?code=auth_code_123&state="+state, resp.Header().Get("Location"))

	mockClientService.AssertExpectations(t)
	mockConsentService.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestAuthorizeHandler_ClientDoesNotExist(t *testing.T) {
	t.Parallel()
	// Setup
	mockAuthService := new(MockAuthorizationService)
	mockConsentService := new(MockConsentService)
	mockClientService := new(MockClientService)
	consentEndpoint := "/oauth2/consent"

	router, _ := setupAuthorizationRouter(
		mockAuthService,
		mockConsentService,
		mockClientService,
		consentEndpoint,
	)

	// Create request with a non-existent client ID
	nonExistentClientID := uuid.New().String()

	req, _ := http.NewRequest(http.MethodGet, "/oauth2/authorize"+
		"?client_id="+nonExistentClientID+
		"&redirect_uri=https://example.com/callback"+
		"&response_type=code"+
		"&scope=read"+
		"&state=xyz123"+
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"+
		"&code_challenge_method=S256", nil)

	resp := httptest.NewRecorder()

	// Mock client service expectations - client not found
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, nonExistentClientID).
		Return(nil, serviceerrors.NewClientNotFoundError(nonExistentClientID))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusFound, resp.Code) // 302 Found for redirect
	redirectLocation := resp.Header().Get("Location")
	assert.Contains(t, redirectLocation, "https://example.com/callback?error=server_error")
	assert.Contains(t, redirectLocation, "client+does+not+exist")

	mockClientService.AssertExpectations(t)
	mockConsentService.AssertNotCalled(t, "ConsentForClientAndUserExists")
	mockAuthService.AssertNotCalled(t, "AuthorizeClient")
}

func TestAuthorizeHandler_ConsentNeeded(t *testing.T) {
	t.Parallel()
	// Setup
	mockAuthService := new(MockAuthorizationService)
	mockConsentService := new(MockConsentService)
	mockClientService := new(MockClientService)
	consentEndpoint := "/oauth2/consent"

	router, _ := setupAuthorizationRouter(
		mockAuthService,
		mockConsentService,
		mockClientService,
		consentEndpoint,
	)

	// Create request with all required query parameters
	clientID := uuid.New().String()

	req, _ := http.NewRequest(http.MethodGet, "/oauth2/authorize"+
		"?client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&response_type=code"+
		"&scope=read"+
		"&state=xyz123"+
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"+
		"&code_challenge_method=S256", nil)

	resp := httptest.NewRecorder()

	// Mock client service expectations
	clientUUID, _ := uuid.Parse(clientID)
	mockClient := &models.Client{
		ID:            clientUUID,
		ResponseTypes: "token",
		RedirectURI:   "https://example.com/callback",
	}

	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).Return(mockClient, nil)

	// Mock consent service expectations - consent does NOT exist
	mockConsentService.On("ConsentForClientAndUserExists", mock.Anything, clientID, mock.Anything).Return(false, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusFound, resp.Code) // 302 Found for redirect to consent page
	assert.Equal(t, "/oauth2/consent", resp.Header().Get("Location"))

	mockClientService.AssertExpectations(t)
	mockConsentService.AssertExpectations(t)
	mockAuthService.AssertNotCalled(t, "AuthorizeClient")
}

func TestAuthorizeHandler_InvalidRequestParams(t *testing.T) {
	t.Parallel()
	// Setup
	mockAuthService := new(MockAuthorizationService)
	mockConsentService := new(MockConsentService)
	mockClientService := new(MockClientService)
	consentEndpoint := "/oauth2/consent"

	router, _ := setupAuthorizationRouter(
		mockAuthService,
		mockConsentService,
		mockClientService,
		consentEndpoint,
	)

	nonExistentClientID := uuid.New().String()

	// Create request with missing required parameters
	req, _ := http.NewRequest(http.MethodGet, "/oauth2/authorize?client_id="+nonExistentClientID, nil)
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_request")

	mockClientService.AssertNotCalled(t, "CheckIfClientExistsByID")
	mockConsentService.AssertNotCalled(t, "ConsentForClientAndUserExists")
	mockAuthService.AssertNotCalled(t, "AuthorizeClient")
}

func TestAuthorizeHandler_AuthorizationError(t *testing.T) {
	t.Parallel()
	// Setup
	mockAuthService := new(MockAuthorizationService)
	mockConsentService := new(MockConsentService)
	mockClientService := new(MockClientService)
	consentEndpoint := "/oauth2/consent"

	router, _ := setupAuthorizationRouter(
		mockAuthService,
		mockConsentService,
		mockClientService,
		consentEndpoint,
	)

	// Create request with all required query parameters
	clientID := uuid.New().String()

	req, _ := http.NewRequest(http.MethodGet, "/oauth2/authorize"+
		"?client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&response_type=code"+
		"&scope=read"+
		"&state=xyz123"+
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"+
		"&code_challenge_method=S256", nil)

	resp := httptest.NewRecorder()

	// Mock client service expectations
	clientUUID, _ := uuid.Parse(clientID)
	mockClient := &models.Client{
		ID:            clientUUID,
		ResponseTypes: "token",
		RedirectURI:   "https://example.com/callback",
	}

	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).Return(mockClient, nil)

	// Mock consent service expectations - consent exists
	mockConsentService.On("ConsentForClientAndUserExists", mock.Anything, clientID, mock.Anything).Return(true, nil)

	// Mock authorization service expectations - error during authorization
	mockAuthService.On("AuthorizeClient", mock.Anything, mock.Anything).
		Return(nil, serviceerrors.NewUnsupportedResponseTypeError(clientID, "token"))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusFound, resp.Code) // 302 Found for redirect
	redirectLocation := resp.Header().Get("Location")
	assert.Contains(t, redirectLocation, "https://example.com/callback?error=unsupported_response_type")

	mockClientService.AssertExpectations(t)
	mockConsentService.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestAuthorizeHandler_ConsentServiceError(t *testing.T) {
	t.Parallel()
	// Setup
	mockAuthService := new(MockAuthorizationService)
	mockConsentService := new(MockConsentService)
	mockClientService := new(MockClientService)
	consentEndpoint := "/oauth2/consent"

	router, _ := setupAuthorizationRouter(
		mockAuthService,
		mockConsentService,
		mockClientService,
		consentEndpoint,
	)

	// Create request with all required query parameters
	clientID := uuid.New().String()

	req, _ := http.NewRequest(http.MethodGet, "/oauth2/authorize"+
		"?client_id="+clientID+
		"&redirect_uri=https://example.com/callback"+
		"&response_type=code"+
		"&scope=read"+
		"&state=xyz123"+
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"+
		"&code_challenge_method=S256", nil)

	resp := httptest.NewRecorder()

	// Mock client service expectations
	clientUUID, _ := uuid.Parse(clientID)
	mockClient := &models.Client{
		ID:            clientUUID,
		ResponseTypes: "token",
		RedirectURI:   "https://example.com/callback",
	}

	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).Return(mockClient, nil)

	// Mock consent service expectations - error checking consent
	mockConsentService.On("ConsentForClientAndUserExists", mock.Anything, clientID, mock.Anything).
		Return(false, errors.New("consent service error"))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusFound, resp.Code) // 302 Found for redirect
	redirectLocation := resp.Header().Get("Location")
	assert.Contains(t, redirectLocation, "https://example.com/callback?error=server_error")
	assert.Contains(t, redirectLocation, "failed+to+verify+consent+status")

	mockClientService.AssertExpectations(t)
	mockConsentService.AssertExpectations(t)
	mockAuthService.AssertNotCalled(t, "AuthorizeClient")
}
