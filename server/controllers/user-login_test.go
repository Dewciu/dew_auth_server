package controllers_test

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockUserService mocks the IUserService interface
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

// MockConsentService mocks the IConsentService interface
type MockConsentService struct {
	mock.Mock
}

func (m *MockConsentService) RevokeConsentForClientAndUser(ctx context.Context, clientID string, userID string) error {
	args := m.Called(ctx, clientID, userID)
	return args.Error(0)
}

func (m *MockConsentService) ConsentForClientAndUserExists(ctx context.Context, clientID string, userID string) (bool, error) {
	args := m.Called(ctx, clientID, userID)
	return args.Bool(0), args.Error(1)
}

func (m *MockConsentService) GrantConsentForClientAndUser(ctx context.Context, clientID string, userID string, scopes string) (*models.Consent, error) {
	args := m.Called(ctx, clientID, userID, scopes)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Consent), args.Error(1)
}

func setupUserLoginRouter(userService *MockUserService, consentService *MockConsentService) (*gin.Engine, *controllers.UserLoginController) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Setup session
	store := cookie.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("test-session", store))

	// Create a test template
	tmpl := template.Must(template.New("login-user.html").Parse(`
		<html>
			<body>
				{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
				{{if .Success}}<div class="success">{{.Success}}</div>{{end}}
				<form method="POST" action="/oauth2/login">
					<input type="email" name="email" />
					<input type="password" name="password" />
					<button type="submit">Login</button>
				</form>
			</body>
		</html>
	`))

	// Create controller
	controller := controllers.NewUserLoginController(tmpl, userService, consentService)

	// Register routes
	router.GET("/oauth2/login", controller.LoginHandler)
	router.POST("/oauth2/login", controller.LoginHandler)

	return router, &controller
}

func TestUserLoginHandler_GetSuccess(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	mockConsentService := new(MockConsentService)
	router, _ := setupUserLoginRouter(mockUserService, mockConsentService)

	// Create request
	req, _ := http.NewRequest(http.MethodGet, "/oauth2/login?redirect_uri=https://example.com/callback", nil)
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "<form method=\"POST\" action=\"/oauth2/login\">")
}

func TestUserLoginHandler_GetMissingRedirectURI(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	mockConsentService := new(MockConsentService)
	router, _ := setupUserLoginRouter(mockUserService, mockConsentService)

	// Create request without redirect_uri
	req, _ := http.NewRequest(http.MethodGet, "/oauth2/login", nil)
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "Redirect URI is required")
}

func TestUserLoginHandler_PostSuccess(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	mockConsentService := new(MockConsentService)
	router, _ := setupUserLoginRouter(mockUserService, mockConsentService)

	// Create form data
	form := url.Values{}
	form.Add("email", "test@example.com")
	form.Add("password", "password123")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/login?redirect_uri=https://example.com/callback",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Mock user service expectations
	userID := uuid.New()
	mockUserService.On("LoginUser", mock.Anything, mock.Anything).Return(&models.User{
		ID:           userID,
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
	}, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "User logged in successfully!")
	mockUserService.AssertExpectations(t)
}

func TestUserLoginHandler_PostInvalidCredentials(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	mockConsentService := new(MockConsentService)
	router, _ := setupUserLoginRouter(mockUserService, mockConsentService)

	// Create form data
	form := url.Values{}
	form.Add("email", "test@example.com")
	form.Add("password", "wrong-password")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/login?redirect_uri=https://example.com/callback",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Mock user service expectations
	mockUserService.On("LoginUser", mock.Anything, mock.Anything).Return(nil,
		serviceerrors.NewInvalidUserPasswordError("test@example.com"))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "Invalid email or password")
	mockUserService.AssertExpectations(t)
}

func TestUserLoginHandler_PostMissingEmail(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	mockConsentService := new(MockConsentService)
	router, _ := setupUserLoginRouter(mockUserService, mockConsentService)

	// Create form data with missing email
	form := url.Values{}
	form.Add("password", "password123")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/login?redirect_uri=https://example.com/callback",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "Email is required")
	mockUserService.AssertNotCalled(t, "LoginUser")
}

func TestUserLoginHandler_PostMissingPassword(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	mockConsentService := new(MockConsentService)
	router, _ := setupUserLoginRouter(mockUserService, mockConsentService)

	// Create form data with missing password
	form := url.Values{}
	form.Add("email", "test@example.com")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/login?redirect_uri=https://example.com/callback",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "Password is required")
	mockUserService.AssertNotCalled(t, "LoginUser")
}

func TestUserLoginHandler_PostWithClientID(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	mockConsentService := new(MockConsentService)
	router, _ := setupUserLoginRouter(mockUserService, mockConsentService)

	// Create form data
	form := url.Values{}
	form.Add("email", "test@example.com")
	form.Add("password", "password123")

	// Create request with client_id in query
	clientID := uuid.New().String()
	req, _ := http.NewRequest(http.MethodPost,
		"/oauth2/login?redirect_uri=https://example.com/callback&client_id="+clientID,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Mock user service expectations
	userID := uuid.New()
	mockUserService.On("LoginUser", mock.Anything, mock.Anything).Return(&models.User{
		ID:           userID,
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
	}, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "User logged in successfully!")

	// Check for session values - need to read cookie
	cookies := resp.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "test-session" {
			sessionCookie = cookie
			break
		}
	}
	assert.NotNil(t, sessionCookie, "Session cookie should be set")

	mockUserService.AssertExpectations(t)
}
