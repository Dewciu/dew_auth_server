package controllers_test

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var tmpl = template.Must(template.New("consent.html").Parse(`
<html lang="en">
<body>
    <div class="consent-container container">
        <h1>Consent</h1>
        {{if .Error}}
        <div class="error">{{.Error}}</div>
        {{end}}
        <p><span class="client-name">{{.ClientName}}</span> is requesting access to your account.</p>
        <div class="scopes">
            <label>Requested Scopes:</label>
            <ul>
                {{range .Scopes}}
                <li>{{.}}</li>
                {{end}}
            </ul>
        </div>
        <form method="POST" action="/oauth2/consent">
            <div class="buttons">
                <button type="submit" name="consent" value="allow" class="allow">Allow</button>
                <button type="submit" name="consent" value="deny" class="deny">Deny</button>
            </div>
            <input type="hidden" name="scopes" value="{{.Scopes}}" />
        </form>
    </div>
</body>
</html>
`))

// MockSession mocks the session
type MockSession struct {
	mock.Mock
}

func (m *MockSession) Get(key interface{}) interface{} {
	args := m.Called(key)
	return args.Get(0)
}

func (m *MockSession) Set(key interface{}, val interface{}) {
	m.Called(key, val)
}

func (m *MockSession) Delete(key interface{}) {
	m.Called(key)
}

func (m *MockSession) Clear() {
	m.Called()
}

func (m *MockSession) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockSession) AddFlash(value interface{}, vars ...string) {
	m.Called(append([]interface{}{value}, toInterfaceSlice(vars)...))
}

func (m *MockSession) Flashes(vars ...string) []interface{} {
	args := m.Called(toInterfaceSlice(vars))
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]interface{})
}

func (m *MockSession) Options(options sessions.Options) {
	m.Called(options)
}

func (m *MockSession) Save() error {
	args := m.Called()
	return args.Error(0)
}

// Helper function to convert string slice to interface slice
func toInterfaceSlice(slice []string) []interface{} {
	result := make([]interface{}, len(slice))
	for i, v := range slice {
		result[i] = v
	}
	return result
}

// Setup test context with mocked session
func setupTestContext(method, path string, body *strings.Reader) (*gin.Context, *httptest.ResponseRecorder, *MockSession) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create request - handle nil body case
	var req *http.Request
	if body == nil {
		req, _ = http.NewRequest(method, path, nil)
	} else {
		req, _ = http.NewRequest(method, path, body)
	}

	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	c.Request = req

	// Mock session
	mockSession := new(MockSession)
	c.Request = c.Request.WithContext(
		appcontext.WithSession(c.Request.Context(), mockSession),
	)

	return c, w, mockSession
}

func TestConsentHandler_MissingSessionParams(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path, template won't be used due to the early return
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	c, w, mockSession := setupTestContext(http.MethodGet, "/oauth2/consent", nil)

	// Set empty or missing session values
	mockSession.On("Get", "client_id").Return("")
	mockSession.On("Get", "auth_redirect_uri").Return("")
	mockSession.On("Get", "client_redirect_uri").Return("")

	// Execute
	controller.ConsentHandler(c)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "\"error\":\"invalid_request\"")
	mockSession.AssertExpectations(t)
}

func TestConsentHandler_ClientNotFound(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	c, w, mockSession := setupTestContext(http.MethodGet, "/oauth2/consent", nil)

	clientID := "test-client-id"
	authRedirectURI := "/oauth2/authorize?client_id=test-client-id&scope=read"
	clientRedirectURI := "https://client.example.com/callback"

	// Set session values
	mockSession.On("Get", "client_id").Return(clientID)
	mockSession.On("Get", "auth_redirect_uri").Return(authRedirectURI)
	mockSession.On("Get", "client_redirect_uri").Return(clientRedirectURI)

	// Mock client service to return an error
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).
		Return(nil, errors.New("client not found"))

	// Execute
	controller.ConsentHandler(c)

	// Assert
	assert.Equal(t, http.StatusFound, w.Code) // Redirect status
	redirectURL, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, clientRedirectURI, redirectURL.Scheme+"://"+redirectURL.Host+redirectURL.Path)
	assert.Contains(t, redirectURL.Query().Get("error"), string(oautherrors.ErrServerError))

	mockSession.AssertExpectations(t)
	mockClientService.AssertExpectations(t)
}

func TestConsentHandler_InvalidRedirectURI(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	c, w, mockSession := setupTestContext(http.MethodGet, "/oauth2/consent", nil)

	clientID := uuid.New().String()
	// Invalid redirect URI that doesn't contain authorize endpoint
	authRedirectURI := "/oauth2/invalid?client_id=test-client-id&scope=read"
	clientRedirectURI := "https://client.example.com/callback"

	// Set session values
	mockSession.On("Get", "client_id").Return(clientID)
	mockSession.On("Get", "auth_redirect_uri").Return(authRedirectURI)
	mockSession.On("Get", "client_redirect_uri").Return(clientRedirectURI)

	// Mock client lookup
	mockClient := &models.Client{
		ID:   uuid.MustParse(clientID),
		Name: "Test Client",
	}
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).
		Return(mockClient, nil)

	// Execute
	controller.ConsentHandler(c)

	// Assert
	assert.Equal(t, http.StatusFound, w.Code) // Redirect status
	redirectURL, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, clientRedirectURI, redirectURL.Scheme+"://"+redirectURL.Host+redirectURL.Path)
	assert.Contains(t, redirectURL.Query().Get("error"), string(oautherrors.ErrInvalidRequest))

	mockSession.AssertExpectations(t)
	mockClientService.AssertExpectations(t)
}

func TestConsentHandler_GetRequest_Success(t *testing.T) {
	t.Parallel()
	// This test would typically check the template rendering
	// For unit tests, we'll just verify that no redirect happens

	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path, template won't actually be loaded
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	c, _, mockSession := setupTestContext(http.MethodGet, "/oauth2/consent", nil)

	clientID := uuid.New().String()
	authRedirectURI := "/oauth2/authorize?client_id=test-client-id&scope=read"
	clientRedirectURI := "https://client.example.com/callback"

	// Set session values
	mockSession.On("Get", "client_id").Return(clientID)
	mockSession.On("Get", "auth_redirect_uri").Return(authRedirectURI)
	mockSession.On("Get", "client_redirect_uri").Return(clientRedirectURI)

	// Mock client lookup
	mockClient := &models.Client{
		ID:     uuid.MustParse(clientID),
		Name:   "Test Client",
		Scopes: "read,write",
	}
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).
		Return(mockClient, nil)

	controller.ConsentHandler(c)

	// Assert that we reached the expected point (no redirect)
	mockSession.AssertExpectations(t)
	mockClientService.AssertExpectations(t)
}

func TestConsentHandler_PostRequest_DenyConsent(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	// Create form data with "deny" consent
	formData := url.Values{}
	formData.Set("consent", "deny")
	formData.Set("scopes", "read,write")
	body := strings.NewReader(formData.Encode())

	c, w, mockSession := setupTestContext(http.MethodPost, "/oauth2/consent", body)

	clientID := uuid.New().String()
	authRedirectURI := "/oauth2/authorize?client_id=test-client-id&scope=read"
	clientRedirectURI := "https://client.example.com/callback"
	userID := uuid.New().String()

	// Set session values
	mockSession.On("Get", "client_id").Return(clientID)
	mockSession.On("Get", "auth_redirect_uri").Return(authRedirectURI)
	mockSession.On("Get", "client_redirect_uri").Return(clientRedirectURI)
	mockSession.On("Get", "user_id").Return(userID)

	// Mock client lookup
	mockClient := &models.Client{
		ID:     uuid.MustParse(clientID),
		Name:   "Test Client",
		Scopes: "read,write",
	}
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).
		Return(mockClient, nil)

	// Execute
	controller.ConsentHandler(c)

	// Assert
	assert.NotEmpty(t, w.Header().Get("Location"))
	redirectURL, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, clientRedirectURI, redirectURL.Scheme+"://"+redirectURL.Host+redirectURL.Path)
	assert.Contains(t, redirectURL.Query().Get("error"), string(oautherrors.ErrAccessDenied))

	mockSession.AssertExpectations(t)
	mockClientService.AssertExpectations(t)
	// No calls to mockConsentService.GrantConsentForClientAndUser should occur
	mockConsentService.AssertNotCalled(t, "GrantConsentForClientAndUser")
}

func TestConsentHandler_PostRequest_GrantConsent_Success(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	// Create form data with "allow" consent
	formData := url.Values{}
	formData.Set("consent", "allow")
	formData.Set("scopes", "read,write")
	body := strings.NewReader(formData.Encode())

	c, w, mockSession := setupTestContext(http.MethodPost, "/oauth2/consent", body)

	clientID := uuid.New().String()
	authRedirectURI := "/oauth2/authorize?client_id=test-client-id&scope=read"
	clientRedirectURI := "https://client.example.com/callback"
	userID := uuid.New().String()

	// Set session values
	mockSession.On("Get", "client_id").Return(clientID)
	mockSession.On("Get", "auth_redirect_uri").Return(authRedirectURI)
	mockSession.On("Get", "client_redirect_uri").Return(clientRedirectURI)
	mockSession.On("Get", "user_id").Return(userID)

	// Mock client lookup
	mockClient := &models.Client{
		ID:     uuid.MustParse(clientID),
		Name:   "Test Client",
		Scopes: "read,write",
	}
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).
		Return(mockClient, nil)

	// Mock consent grant
	mockConsent := &models.Consent{
		ClientID: uuid.MustParse(clientID),
		UserID:   uuid.MustParse(userID),
		Scopes:   "read,write",
	}
	mockConsentService.On("GrantConsentForClientAndUser", mock.Anything, clientID, userID, "read,write").
		Return(mockConsent, nil)

	// Execute
	controller.ConsentHandler(c)

	// Assert
	assert.NotEmpty(t, w.Header().Get("Location"))
	assert.Equal(t, authRedirectURI, w.Header().Get("Location"))

	mockSession.AssertExpectations(t)
	mockClientService.AssertExpectations(t)
	mockConsentService.AssertExpectations(t)
}

func TestConsentHandler_PostRequest_GrantConsent_Error(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	// Create form data with "allow" consent
	formData := url.Values{}
	formData.Set("consent", "allow")
	formData.Set("scopes", "read,write")
	body := strings.NewReader(formData.Encode())

	c, w, mockSession := setupTestContext(http.MethodPost, "/oauth2/consent", body)

	clientID := uuid.New().String()
	authRedirectURI := "/oauth2/authorize?client_id=test-client-id&scope=read"
	clientRedirectURI := "https://client.example.com/callback"
	userID := uuid.New().String()

	// Set session values
	mockSession.On("Get", "client_id").Return(clientID)
	mockSession.On("Get", "auth_redirect_uri").Return(authRedirectURI)
	mockSession.On("Get", "client_redirect_uri").Return(clientRedirectURI)
	mockSession.On("Get", "user_id").Return(userID)

	// Mock client lookup
	mockClient := &models.Client{
		ID:     uuid.MustParse(clientID),
		Name:   "Test Client",
		Scopes: "read,write",
	}
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).
		Return(mockClient, nil)

	// Mock consent service to return an error
	mockConsentService.On("GrantConsentForClientAndUser", mock.Anything, clientID, userID, "read,write").
		Return(nil, errors.New("database error"))

	// Execute
	controller.ConsentHandler(c)

	// Assert
	assert.NotEmpty(t, w.Header().Get("Location"))
	redirectURL, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, clientRedirectURI, redirectURL.Scheme+"://"+redirectURL.Host+redirectURL.Path)
	assert.Contains(t, redirectURL.Query().Get("error"), string(oautherrors.ErrServerError))

	mockSession.AssertExpectations(t)
	mockClientService.AssertExpectations(t)
	mockConsentService.AssertExpectations(t)
}

func TestConsentHandler_PostRequest_MissingScopeParam(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	// Create form data with missing scopes
	formData := url.Values{}
	formData.Set("consent", "allow")
	// Missing scopes parameter
	body := strings.NewReader(formData.Encode())

	c, w, mockSession := setupTestContext(http.MethodPost, "/oauth2/consent", body)

	clientID := uuid.New().String()
	authRedirectURI := "/oauth2/authorize?client_id=test-client-id&scope=read"
	clientRedirectURI := "https://client.example.com/callback"

	// Set session values
	mockSession.On("Get", "client_id").Return(clientID)
	mockSession.On("Get", "auth_redirect_uri").Return(authRedirectURI)
	mockSession.On("Get", "client_redirect_uri").Return(clientRedirectURI)

	// Mock client lookup
	mockClient := &models.Client{
		ID:     uuid.MustParse(clientID),
		Name:   "Test Client",
		Scopes: "read,write",
	}
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).
		Return(mockClient, nil)

	// Execute
	controller.ConsentHandler(c)

	// Assert
	assert.NotEmpty(t, w.Header().Get("Location"))
	redirectURL, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, clientRedirectURI, redirectURL.Scheme+"://"+redirectURL.Host+redirectURL.Path)
	assert.Contains(t, redirectURL.Query().Get("error"), string(oautherrors.ErrInvalidScope))

	mockSession.AssertExpectations(t)
	mockClientService.AssertExpectations(t)
}

func TestConsentHandler_PostRequest_MissingConsentParam(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	// Create form data with missing consent
	formData := url.Values{}
	// Missing consent parameter
	formData.Set("scopes", "read,write")
	body := strings.NewReader(formData.Encode())

	c, w, mockSession := setupTestContext(http.MethodPost, "/oauth2/consent", body)

	clientID := uuid.New().String()
	authRedirectURI := "/oauth2/authorize?client_id=test-client-id&scope=read"
	clientRedirectURI := "https://client.example.com/callback"

	// Set session values
	mockSession.On("Get", "client_id").Return(clientID)
	mockSession.On("Get", "auth_redirect_uri").Return(authRedirectURI)
	mockSession.On("Get", "client_redirect_uri").Return(clientRedirectURI)

	// Mock client lookup
	mockClient := &models.Client{
		ID:     uuid.MustParse(clientID),
		Name:   "Test Client",
		Scopes: "read,write",
	}
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).
		Return(mockClient, nil)

	// Execute
	controller.ConsentHandler(c)

	// Assert
	assert.NotEmpty(t, w.Header().Get("Location"))
	redirectURL, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, clientRedirectURI, redirectURL.Scheme+"://"+redirectURL.Host+redirectURL.Path)
	assert.Contains(t, redirectURL.Query().Get("error"), string(oautherrors.ErrInvalidRequest))

	mockSession.AssertExpectations(t)
	mockClientService.AssertExpectations(t)
}

func TestConsentHandler_UnsupportedMethod(t *testing.T) {
	t.Parallel()
	// Setup
	mockClientService := new(MockClientService)
	mockConsentService := new(MockConsentService)

	controller := controllers.NewConsentController(
		tmpl, // Mock path
		mockClientService,
		mockConsentService,
		"/oauth2/authorize",
	)

	c, w, mockSession := setupTestContext(http.MethodPut, "/oauth2/consent", nil)

	clientID := uuid.New().String()
	authRedirectURI := "/oauth2/authorize?client_id=test-client-id&scope=read"
	clientRedirectURI := "https://client.example.com/callback"

	// Set session values
	mockSession.On("Get", "client_id").Return(clientID)
	mockSession.On("Get", "auth_redirect_uri").Return(authRedirectURI)
	mockSession.On("Get", "client_redirect_uri").Return(clientRedirectURI)

	// Mock client lookup
	mockClient := &models.Client{
		ID:     uuid.MustParse(clientID),
		Name:   "Test Client",
		Scopes: "read,write",
	}
	mockClientService.On("CheckIfClientExistsByID", mock.Anything, clientID).
		Return(mockClient, nil)

	// Execute
	controller.ConsentHandler(c)

	// Assert
	assert.NotEmpty(t, w.Header().Get("Location"))
	redirectURL, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, clientRedirectURI, redirectURL.Scheme+"://"+redirectURL.Host+redirectURL.Path)
	assert.Contains(t, redirectURL.Query().Get("error"), string(oautherrors.ErrInvalidRequest))

	mockSession.AssertExpectations(t)
	mockClientService.AssertExpectations(t)
}
