package controllers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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

var revocationClientID = uuid.New()

func setupRevocationRouter(accessTokenService *MockAccessTokenService, refreshTokenService *MockRefreshTokenService) (*gin.Engine, *controllers.RevocationController) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Create controller
	controller := controllers.NewRevocationController(
		accessTokenService,
		refreshTokenService,
	)

	// Register route with middleware to set client in context
	router.POST("/oauth2/revoke", func(c *gin.Context) {
		// Simulate middleware that would set the client in context
		client := &models.Client{
			ID:   revocationClientID,
			Name: "Test Client",
		}
		c.Request = c.Request.WithContext(appcontext.WithClient(c.Request.Context(), client))
		controller.Revoke(c)
	})

	// Register error handlers
	ginerr.RegisterErrorHandler(oautherrors.OAuthUnsupportedTokenTypeErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthInputValidationErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthInternalServerErrorHandler)

	return router, &controller
}

func TestRevokeHandler_AccessTokenSuccess(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	revocationInput := inputs.IntrospectionRevocationInput{
		Token:     "test-access-token",
		TokenType: string(constants.TokenTypeAccess),
	}
	jsonData, _ := json.Marshal(revocationInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock access token service expectations
	userID := "test-user-id"

	mockToken := &cachemodels.AccessToken{
		Token:     "test-access-token",
		TokenType: constants.TokenTypeBearer,
		ClientID:  revocationClientID.String(),
		UserID:    userID,
		Scopes:    "read write",
	}

	mockAccessTokenService.On("GetTokenDetails", mock.Anything, "test-access-token").Return(mockToken, nil)
	mockAccessTokenService.On("RevokeToken", mock.Anything, mockToken).Return(nil)

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

func TestRevokeHandler_AccessTokenInvalidOrExpired(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	revocationInput := inputs.IntrospectionRevocationInput{
		Token:     "invalid-access-token",
		TokenType: string(constants.TokenTypeAccess),
	}
	jsonData, _ := json.Marshal(revocationInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock access token service expectations - token not found
	mockAccessTokenService.On("GetTokenDetails", mock.Anything, "invalid-access-token").
		Return(nil, serviceerrors.NewTokenNotFoundError("invalid-access-token"))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, false, responseBody["active"])

	mockAccessTokenService.AssertExpectations(t)
	mockAccessTokenService.AssertNotCalled(t, "RevokeToken")
}

func TestRevokeHandler_AccessTokenClientMismatch(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	revocationInput := inputs.IntrospectionRevocationInput{
		Token:     "other-client-token",
		TokenType: string(constants.TokenTypeAccess),
	}
	jsonData, _ := json.Marshal(revocationInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock access token service expectations - token from different client
	userID := "test-user-id"
	differentClientID := uuid.New().String() // Not matching the client in context

	mockToken := &cachemodels.AccessToken{
		Token:     "other-client-token",
		TokenType: constants.TokenTypeBearer,
		ClientID:  differentClientID, // Different client ID
		UserID:    userID,
		Scopes:    "read write",
	}

	mockAccessTokenService.On("GetTokenDetails", mock.Anything, "other-client-token").Return(mockToken, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, false, responseBody["active"])

	mockAccessTokenService.AssertExpectations(t)
	mockAccessTokenService.AssertNotCalled(t, "RevokeToken")
}

func TestRevokeHandler_AccessTokenRevocationError(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	revocationInput := inputs.IntrospectionRevocationInput{
		Token:     "error-token",
		TokenType: string(constants.TokenTypeAccess),
	}
	jsonData, _ := json.Marshal(revocationInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock access token service expectations
	userID := "test-user-id"

	mockToken := &cachemodels.AccessToken{
		Token:     "error-token",
		TokenType: constants.TokenTypeBearer,
		ClientID:  revocationClientID.String(),
		UserID:    userID,
		Scopes:    "read write",
	}

	mockAccessTokenService.On("GetTokenDetails", mock.Anything, "error-token").Return(mockToken, nil)
	mockAccessTokenService.On("RevokeToken", mock.Anything, mockToken).Return(errors.New("revocation error"))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.Contains(t, resp.Body.String(), "internal_server_error")

	mockAccessTokenService.AssertExpectations(t)
}

func TestRevokeHandler_RefreshTokenSuccess(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	revocationInput := inputs.IntrospectionRevocationInput{
		Token:     "test-refresh-token",
		TokenType: string(constants.TokenTypeRefresh),
	}
	jsonData, _ := json.Marshal(revocationInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock refresh token service expectations
	userID := "test-user-id"

	mockToken := &cachemodels.RefreshToken{
		Token:    "test-refresh-token",
		ClientID: revocationClientID.String(),
		UserID:   userID,
		Scopes:   "read write",
		Revoked:  false,
	}

	mockRefreshTokenService.On("GetTokenDetails", mock.Anything, "test-refresh-token").Return(mockToken, nil)
	mockRefreshTokenService.On("RevokeToken", mock.Anything, mockToken).Return(nil)

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

func TestRevokeHandler_RefreshTokenInvalidOrExpired(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	revocationInput := inputs.IntrospectionRevocationInput{
		Token:     "invalid-refresh-token",
		TokenType: string(constants.TokenTypeRefresh),
	}
	jsonData, _ := json.Marshal(revocationInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock refresh token service expectations - token not found
	mockRefreshTokenService.On("GetTokenDetails", mock.Anything, "invalid-refresh-token").
		Return(nil, serviceerrors.NewTokenNotFoundError("invalid-refresh-token"))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, false, responseBody["active"])

	mockRefreshTokenService.AssertExpectations(t)
	mockRefreshTokenService.AssertNotCalled(t, "RevokeToken")
}

func TestRevokeHandler_RefreshTokenClientMismatch(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	revocationInput := inputs.IntrospectionRevocationInput{
		Token:     "other-client-refresh-token",
		TokenType: string(constants.TokenTypeRefresh),
	}
	jsonData, _ := json.Marshal(revocationInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock refresh token service expectations - token from different client
	userID := "test-user-id"
	differentClientID := uuid.New().String() // Not matching the client in context

	mockToken := &cachemodels.RefreshToken{
		Token:    "other-client-refresh-token",
		ClientID: differentClientID, // Different client ID
		UserID:   userID,
		Scopes:   "read write",
		Revoked:  false,
	}

	mockRefreshTokenService.On("GetTokenDetails", mock.Anything, "other-client-refresh-token").Return(mockToken, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, false, responseBody["active"])

	mockRefreshTokenService.AssertExpectations(t)
	mockRefreshTokenService.AssertNotCalled(t, "RevokeToken")
}

func TestRevokeHandler_RefreshTokenRevocationError(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body
	revocationInput := inputs.IntrospectionRevocationInput{
		Token:     "error-refresh-token",
		TokenType: string(constants.TokenTypeRefresh),
	}
	jsonData, _ := json.Marshal(revocationInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Mock refresh token service expectations
	userID := "test-user-id"

	mockToken := &cachemodels.RefreshToken{
		Token:    "error-refresh-token",
		ClientID: revocationClientID.String(),
		UserID:   userID,
		Scopes:   "read write",
		Revoked:  false,
	}

	mockRefreshTokenService.On("GetTokenDetails", mock.Anything, "error-refresh-token").Return(mockToken, nil)
	mockRefreshTokenService.On("RevokeToken", mock.Anything, mockToken).Return(errors.New("revocation error"))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.Contains(t, resp.Body.String(), "internal_server_error")

	mockRefreshTokenService.AssertExpectations(t)
}

func TestRevokeHandler_UnsupportedTokenType(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create JSON request body with unsupported token type
	revocationInput := inputs.IntrospectionRevocationInput{
		Token:     "test-token",
		TokenType: "unsupported_type",
	}
	jsonData, _ := json.Marshal(revocationInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "unsupported_token_type")

	mockAccessTokenService.AssertNotCalled(t, "GetTokenDetails")
	mockAccessTokenService.AssertNotCalled(t, "RevokeToken")
	mockRefreshTokenService.AssertNotCalled(t, "GetTokenDetails")
	mockRefreshTokenService.AssertNotCalled(t, "RevokeToken")
}

func TestRevokeHandler_InvalidInput(t *testing.T) {
	t.Parallel()
	// Setup
	mockAccessTokenService := new(MockAccessTokenService)
	mockRefreshTokenService := new(MockRefreshTokenService)
	router, _ := setupRevocationRouter(mockAccessTokenService, mockRefreshTokenService)

	// Create invalid JSON request body (missing required fields)
	invalidInput := map[string]string{
		"some_field": "some_value",
	}
	jsonData, _ := json.Marshal(invalidInput)

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_request")

	mockAccessTokenService.AssertNotCalled(t, "GetTokenDetails")
	mockAccessTokenService.AssertNotCalled(t, "RevokeToken")
	mockRefreshTokenService.AssertNotCalled(t, "GetTokenDetails")
	mockRefreshTokenService.AssertNotCalled(t, "RevokeToken")
}
