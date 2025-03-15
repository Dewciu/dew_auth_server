package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ing-bank/ginerr/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var globalClientID = uuid.New()

// MockAccessTokenService mocks the IAccessTokenService interface
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

// MockRefreshTokenService mocks the IRefreshTokenService interface for introspection tests
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

func setupIntrospectionRouter(accessTokenService *MockAccessTokenService, refreshTokenService *MockRefreshTokenService) (*gin.Engine, *controllers.IntrospectionController) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Create controller
	controller := controllers.NewIntrospectionController(
		accessTokenService,
		refreshTokenService,
	)

	// Register route with middleware to set client in context
	router.POST("/oauth2/introspect", func(c *gin.Context) {
		// Simulate middleware that would set the client in context
		client := &models.Client{
			ID:   globalClientID,
			Name: "Test Client",
		}
		c.Request = c.Request.WithContext(appcontext.WithClient(c.Request.Context(), client))
		controller.Introspect(c)
	})

	ginerr.RegisterErrorHandler(oautherrors.OAuthUnsupportedTokenTypeErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthInputValidationErrorHandler)

	return router, &controller
}

func TestIntrospectHandler_AccessTokenActive(t *testing.T) {
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupIntrospectionRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	introspectionInput := inputs.IntrospectionRevocationInput{
		Token:     "test-access-token",
		TokenType: string(constants.TokenTypeAccess),
	}
	jsonData, _ := json.Marshal(introspectionInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock access token service expectations
	userID := "test-user-id"
	expiresIn := int(time.Now().Add(time.Hour).Unix()) // 1 hour from now

	mockToken := &cachemodels.AccessToken{
		Token:     "test-access-token",
		TokenType: constants.TokenTypeBearer,
		ClientID:  globalClientID.String(),
		UserID:    userID,
		Scopes:    "read write",
		ExpiresIn: expiresIn,
		IssuedAt:  int(time.Now().Unix()),
		NotBefore: int(time.Now().Unix()),
	}

	mockAccessTokenService.On("GetTokenDetails", mock.Anything, "test-access-token").Return(mockToken, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, true, responseBody["active"])
	assert.Equal(t, "read write", responseBody["scopes"])
	assert.Equal(t, globalClientID.String(), responseBody["client_id"])
	assert.Equal(t, userID, responseBody["user_id"])
	assert.Equal(t, "Bearer", responseBody["token_type"])

	mockAccessTokenService.AssertExpectations(t)
}

func TestIntrospectHandler_AccessTokenInactive(t *testing.T) {
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupIntrospectionRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	introspectionInput := inputs.IntrospectionRevocationInput{
		Token:     "expired-access-token",
		TokenType: string(constants.TokenTypeAccess),
	}
	jsonData, _ := json.Marshal(introspectionInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	userID := "test-user-id"
	expiresIn := int(time.Now().Add(-1 * time.Hour).Unix()) // 1 hour ago (expired)

	mockToken := &cachemodels.AccessToken{
		Token:     "expired-access-token",
		TokenType: constants.TokenTypeBearer,
		ClientID:  globalClientID.String(),
		UserID:    userID,
		Scopes:    "read write",
		ExpiresIn: expiresIn, // Expired token
		IssuedAt:  int(time.Now().Add(-2 * time.Hour).Unix()),
		NotBefore: int(time.Now().Add(-2 * time.Hour).Unix()),
	}

	mockAccessTokenService.On("GetTokenDetails", mock.Anything, "expired-access-token").Return(mockToken, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, false, responseBody["active"])

	mockAccessTokenService.AssertExpectations(t)
}

func TestIntrospectHandler_AccessTokenNotFound(t *testing.T) {
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupIntrospectionRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	introspectionInput := inputs.IntrospectionRevocationInput{
		Token:     "non-existent-token",
		TokenType: string(constants.TokenTypeAccess),
	}
	jsonData, _ := json.Marshal(introspectionInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock access token service expectations
	mockAccessTokenService.On("GetTokenDetails", mock.Anything, "non-existent-token").
		Return(nil, serviceerrors.NewTokenNotFoundError("non-existent-token"))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, false, responseBody["active"])

	mockAccessTokenService.AssertExpectations(t)
}

func TestIntrospectHandler_RefreshTokenActive(t *testing.T) {
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupIntrospectionRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	introspectionInput := inputs.IntrospectionRevocationInput{
		Token:     "test-refresh-token",
		TokenType: string(constants.TokenTypeRefresh),
	}
	jsonData, _ := json.Marshal(introspectionInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	userID := "test-user-id"
	expiresIn := int(time.Now().Add(24 * time.Hour).Unix()) // 24 hours from now

	mockToken := &cachemodels.RefreshToken{
		Token:     "test-refresh-token",
		ClientID:  globalClientID.String(),
		UserID:    userID,
		Scopes:    "read write",
		ExpiresIn: expiresIn,
		IssuedAt:  int(time.Now().Unix()),
		Revoked:   false,
	}

	mockRefreshTokenService.On("GetTokenDetails", mock.Anything, "test-refresh-token").Return(mockToken, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, true, responseBody["active"])
	assert.Equal(t, "read write", responseBody["scopes"])
	assert.Equal(t, globalClientID.String(), responseBody["client_id"])
	assert.Equal(t, userID, responseBody["user_id"])

	mockRefreshTokenService.AssertExpectations(t)
}

func TestIntrospectHandler_RefreshTokenRevoked(t *testing.T) {
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupIntrospectionRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	introspectionInput := inputs.IntrospectionRevocationInput{
		Token:     "revoked-refresh-token",
		TokenType: string(constants.TokenTypeRefresh),
	}
	jsonData, _ := json.Marshal(introspectionInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock refresh token service expectations
	clientID := uuid.New().String()
	userID := "test-user-id"
	expiresIn := int(time.Now().Add(24 * time.Hour).Unix()) // 24 hours from now

	mockToken := &cachemodels.RefreshToken{
		Token:     "revoked-refresh-token",
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    "read write",
		ExpiresIn: expiresIn,
		IssuedAt:  int(time.Now().Unix()),
		Revoked:   true, // Revoked token
	}

	mockRefreshTokenService.On("GetTokenDetails", mock.Anything, "revoked-refresh-token").Return(mockToken, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, false, responseBody["active"])

	mockRefreshTokenService.AssertExpectations(t)
}

func TestIntrospectHandler_UnsupportedTokenType(t *testing.T) {
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupIntrospectionRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body with unsupported token type
	introspectionInput := inputs.IntrospectionRevocationInput{
		Token:     "test-token",
		TokenType: "unsupported_type",
	}
	jsonData, _ := json.Marshal(introspectionInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "unsupported_token_type")

	mockAccessTokenService.AssertNotCalled(t, "GetTokenDetails")
	mockRefreshTokenService.AssertNotCalled(t, "GetTokenDetails")
}

func TestIntrospectHandler_InvalidInput(t *testing.T) {
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupIntrospectionRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create invalid JSON request body (missing required fields)
	invalidInput := map[string]string{
		"some_field": "some_value",
	}
	jsonData, _ := json.Marshal(invalidInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_request")

	mockAccessTokenService.AssertNotCalled(t, "GetTokenDetails")
	mockRefreshTokenService.AssertNotCalled(t, "GetTokenDetails")
}

func TestIntrospectHandler_ClientMismatch(t *testing.T) {
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupIntrospectionRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	introspectionInput := inputs.IntrospectionRevocationInput{
		Token:     "client-mismatch-token",
		TokenType: string(constants.TokenTypeAccess),
	}
	jsonData, _ := json.Marshal(introspectionInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock access token service expectations
	differentClientID := uuid.New().String() // Different from the one in context
	userID := "test-user-id"
	expiresIn := int(time.Now().Add(time.Hour).Unix())

	mockToken := &cachemodels.AccessToken{
		Token:     "client-mismatch-token",
		TokenType: constants.TokenTypeBearer,
		ClientID:  differentClientID, // Different client ID
		UserID:    userID,
		Scopes:    "read write",
		ExpiresIn: expiresIn,
		IssuedAt:  int(time.Now().Unix()),
		NotBefore: int(time.Now().Unix()),
	}

	mockAccessTokenService.On("GetTokenDetails", mock.Anything, "client-mismatch-token").Return(mockToken, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	// Token should be reported as inactive due to client mismatch
	assert.Equal(t, false, responseBody["active"])

	mockAccessTokenService.AssertExpectations(t)
}
