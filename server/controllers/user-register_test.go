package controllers_test

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupUserRegisterRouter(userService *MockUserService) (*gin.Engine, *controllers.UserRegisterController) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Create a test template
	tmpl := template.Must(template.New("register-user.html").Parse(`
		<html>
			<body>
				{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
				{{if .Success}}<div class="success">{{.Success}}</div>{{end}}
				<form method="POST" action="/register-user">
					<input type="text" name="username" />
					<input type="email" name="email" />
					<input type="password" name="password" />
					<button type="submit">Register</button>
				</form>
			</body>
		</html>
	`))

	// Create controller
	controller := controllers.NewUserRegisterController(tmpl, userService)

	// Register routes
	router.GET("/oauth2/register-user", controller.RegisterHandler)
	router.POST("/oauth2/register-user", controller.RegisterHandler)

	return router, &controller
}

func TestUserRegisterHandler_GetSuccess(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	router, _ := setupUserRegisterRouter(mockUserService)

	// Create request
	req, _ := http.NewRequest(http.MethodGet, "/oauth2/register-user", nil)
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "<form method=\"POST\" action=\"/register-user\">")
}

func TestUserRegisterHandler_PostSuccess(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	router, _ := setupUserRegisterRouter(mockUserService)

	// Create form data
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("email", "test@example.com")
	form.Add("password", "password123")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-user",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Mock user service expectations
	mockUserService.On("RegisterUser", mock.Anything, mock.MatchedBy(func(input *inputs.UserRegisterInput) bool {
		return input.Username == "testuser" &&
			input.Email == "test@example.com" &&
			input.Password == "password123"
	})).Return(nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "User registered successfully!")
	mockUserService.AssertExpectations(t)
}

func TestUserRegisterHandler_PostMissingUsername(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	router, _ := setupUserRegisterRouter(mockUserService)

	// Create form data with missing username
	form := url.Values{}
	form.Add("email", "test@example.com")
	form.Add("password", "password123")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-user",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "username is required")
	mockUserService.AssertNotCalled(t, "RegisterUser")
}

func TestUserRegisterHandler_PostMissingEmail(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	router, _ := setupUserRegisterRouter(mockUserService)

	// Create form data with missing email
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "password123")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-user",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "email is required")
	mockUserService.AssertNotCalled(t, "RegisterUser")
}

func TestUserRegisterHandler_PostMissingPassword(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	router, _ := setupUserRegisterRouter(mockUserService)

	// Create form data with missing password
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("email", "test@example.com")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-user",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "password is required")
	mockUserService.AssertNotCalled(t, "RegisterUser")
}

func TestUserRegisterHandler_PostUserAlreadyExists(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	router, _ := setupUserRegisterRouter(mockUserService)

	// Create form data
	form := url.Values{}
	form.Add("username", "existinguser")
	form.Add("email", "existing@example.com")
	form.Add("password", "password123")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-user",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Mock user service expectations
	mockUserService.On("RegisterUser", mock.Anything, mock.Anything).Return(
		serviceerrors.NewUserAlreadyExistsError("existing@example.com", "existinguser"))

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "User already exists")
	mockUserService.AssertExpectations(t)
}

func TestUserRegisterHandler_PostServiceError(t *testing.T) {
	// Setup
	mockUserService := new(MockUserService)
	router, _ := setupUserRegisterRouter(mockUserService)

	// Create form data
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("email", "test@example.com")
	form.Add("password", "password123")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-user",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Mock user service expectations for a general error
	mockUserService.On("RegisterUser", mock.Anything, mock.Anything).Return(
		assert.AnError)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "An error occurred while registering the user")
	mockUserService.AssertExpectations(t)
}
