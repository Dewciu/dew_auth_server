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
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClientService mocks the IClientService interface
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

// MockClientRegisterOutput implements IClientRegisterOutput for testing
type MockClientRegisterOutput struct {
	ClientID     string
	ClientSecret string
}

func (o *MockClientRegisterOutput) GetClientID() string {
	return o.ClientID
}

func (o *MockClientRegisterOutput) GetClientSecret() string {
	return o.ClientSecret
}

func setupClientRegisterRouter(clientService *MockClientService) (*gin.Engine, *controllers.ClientRegisterController) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Create a test template
	tmpl := template.Must(template.New("register-client.html").Parse(`
		<html>
			<body>
				{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
				{{if .Success}}
					<div class="success">{{.Success}}</div>
					<div class="client-info">
						<p>Client ID: <span>{{.ClientID}}</span></p>
						<p>Client Secret: <span>{{.ClientSecret}}</span></p>
					</div>
				{{end}}
				<form method="POST" action="/register-client">
					<input type="text" name="client_name" />
					<input type="email" name="client_email" />
					<input type="url" name="redirect_uri" />
					<div class="checkbox-container">
						<input type="checkbox" name="code_response_type" value="code" />
					</div>
					<div class="checkbox-container">
						<input type="checkbox" name="authorization_code_grant_type" value="authorization_code" />
					</div>
					<div class="checkbox-container">
						<input type="checkbox" name="read_scope" value="read" />
					</div>
					<button type="submit">Register</button>
				</form>
			</body>
		</html>
	`))

	// Create controller
	controller := controllers.NewRegisterController(tmpl, clientService)

	// Register routes
	router.GET("/oauth2/register-client", controller.RegisterHandler)
	router.POST("/oauth2/register-client", controller.RegisterHandler)

	return router, &controller
}

func TestClientRegisterHandler_GetSuccess(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	router, _ := setupClientRegisterRouter(mockClientService)

	// Create request
	req, _ := http.NewRequest(http.MethodGet, "/oauth2/register-client", nil)
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "<form method=\"POST\" action=\"/register-client\">")
}

func TestClientRegisterHandler_PostSuccess(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	router, _ := setupClientRegisterRouter(mockClientService)

	// Create form data
	form := url.Values{}
	form.Add("client_name", "Test Client")
	form.Add("client_email", "client@example.com")
	form.Add("redirect_uri", "https://client.example.com/callback")
	form.Add("code_response_type", "code")
	form.Add("authorization_code_grant_type", "authorization_code")
	form.Add("read_scope", "read")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-client",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Mock client service expectations
	clientID := uuid.New().String()
	clientSecret := "test-client-secret"
	mockOutput := &MockClientRegisterOutput{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	mockClientService.On("RegisterClient", mock.Anything, mock.MatchedBy(func(input inputs.IClientRegisterInput) bool {
		return input.GetClientName() == "Test Client" &&
			input.GetClientEmail() == "client@example.com" &&
			input.GetRedirectURI() == "https://client.example.com/callback" &&
			input.GetResponseTypes() == "code" &&
			input.GetGrantTypes() == "authorization_code" &&
			input.GetScopes() == "read"
	})).Return(mockOutput, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "Client registered successfully!")
	assert.Contains(t, resp.Body.String(), clientID)
	assert.Contains(t, resp.Body.String(), clientSecret)
	mockClientService.AssertExpectations(t)
}

func TestClientRegisterHandler_PostMissingClientName(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	router, _ := setupClientRegisterRouter(mockClientService)

	// Create form data with missing client_name
	form := url.Values{}
	form.Add("client_email", "client@example.com")
	form.Add("redirect_uri", "https://client.example.com/callback")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-client",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "client_name is required")
	mockClientService.AssertNotCalled(t, "RegisterClient")
}

func TestClientRegisterHandler_PostMissingClientEmail(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	router, _ := setupClientRegisterRouter(mockClientService)

	// Create form data with missing client_email
	form := url.Values{}
	form.Add("client_name", "Test Client")
	form.Add("redirect_uri", "https://client.example.com/callback")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-client",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "client_email is required")
	mockClientService.AssertNotCalled(t, "RegisterClient")
}

func TestClientRegisterHandler_PostMissingRedirectURI(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	router, _ := setupClientRegisterRouter(mockClientService)

	// Create form data with missing redirect_uri
	form := url.Values{}
	form.Add("client_name", "Test Client")
	form.Add("client_email", "client@example.com")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-client",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "redirect_uri is required")
	mockClientService.AssertNotCalled(t, "RegisterClient")
}

func TestClientRegisterHandler_PostRegistrationError(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	router, _ := setupClientRegisterRouter(mockClientService)

	// Create form data
	form := url.Values{}
	form.Add("client_name", "Test Client")
	form.Add("client_email", "client@example.com")
	form.Add("redirect_uri", "https://client.example.com/callback")
	form.Add("code_response_type", "code")
	form.Add("authorization_code_grant_type", "authorization_code")
	form.Add("read_scope", "read")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-client",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Mock client service expectations for an error
	mockClientService.On("RegisterClient", mock.Anything, mock.Anything).Return(nil, assert.AnError)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "assert.AnError general error for testing")
	mockClientService.AssertExpectations(t)
}

func TestClientRegisterHandler_PostWithMultipleScopes(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	router, _ := setupClientRegisterRouter(mockClientService)

	// Create form data with multiple scopes
	form := url.Values{}
	form.Add("client_name", "Test Client")
	form.Add("client_email", "client@example.com")
	form.Add("redirect_uri", "https://client.example.com/callback")
	form.Add("code_response_type", "code")
	form.Add("authorization_code_grant_type", "authorization_code")
	form.Add("read_scope", "read")
	form.Add("write_scope", "write")
	form.Add("delete_scope", "delete")

	// Create request
	req, _ := http.NewRequest(http.MethodPost, "/oauth2/register-client",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	// Mock client service expectations
	clientID := uuid.New().String()
	clientSecret := "test-client-secret"
	mockOutput := &MockClientRegisterOutput{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	mockClientService.On("RegisterClient", mock.Anything, mock.MatchedBy(func(input inputs.IClientRegisterInput) bool {
		// Check that all three scopes are present in any order
		scopes := input.GetScopes()
		return strings.Contains(scopes, "read") &&
			strings.Contains(scopes, "write") &&
			strings.Contains(scopes, "delete")
	})).Return(mockOutput, nil)

	// Act
	router.ServeHTTP(resp, req)

	// Assert
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "Client registered successfully!")
	mockClientService.AssertExpectations(t)
}
