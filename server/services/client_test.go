package services_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClientRepository is a mock implementation of the IClientRepository interface
type MockClientRepository struct {
	mock.Mock
}

func (m *MockClientRepository) GetWithID(ctx context.Context, id string) (*models.Client, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientRepository) GetWithName(ctx context.Context, name string) (*models.Client, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientRepository) Create(ctx context.Context, client *models.Client) error {
	args := m.Called(ctx, client)
	return args.Error(0)
}

// MockClientRegisterInput is a mock implementation of the IClientRegisterInput interface
type MockClientRegisterInput struct {
	mock.Mock
}

func (m *MockClientRegisterInput) GetClientName() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockClientRegisterInput) GetClientEmail() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockClientRegisterInput) GetRedirectURI() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockClientRegisterInput) GetResponseTypes() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockClientRegisterInput) GetGrantTypes() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockClientRegisterInput) GetScopes() string {
	args := m.Called()
	return args.String(0)
}

func TestVerifyClient_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockClientRepository)
	clientService := services.NewClientService(mockRepo)

	clientID := uuid.New().String()
	clientSecret := "test-secret"

	// Encode the secret for storage comparison
	encodedSecret := base64.StdEncoding.EncodeToString([]byte(clientSecret))

	expectedClient := &models.Client{
		ID:     uuid.MustParse(clientID),
		Secret: encodedSecret,
		Name:   "Test Client",
	}

	mockRepo.On("GetWithID", ctx, clientID).Return(expectedClient, nil)

	// Execute
	client, err := clientService.VerifyClient(ctx, clientID, clientSecret)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, expectedClient, client)
	mockRepo.AssertExpectations(t)
}

func TestVerifyClient_ClientNotFound(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockClientRepository)
	clientService := services.NewClientService(mockRepo)

	clientID := "non-existent-client"
	clientSecret := "test-secret"

	mockRepo.On("GetWithID", ctx, clientID).Return(nil, repositories.NewRecordNotFoundError[models.Client](models.Client{}))

	// Execute
	client, err := clientService.VerifyClient(ctx, clientID, clientSecret)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.IsType(t, serviceerrors.ClientNotFoundError{}, err)
	mockRepo.AssertExpectations(t)
}

func TestVerifyClient_InvalidSecret(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockClientRepository)
	clientService := services.NewClientService(mockRepo)

	clientID := uuid.New().String()
	clientSecret := "wrong-secret"

	// Encode a different secret for storage
	correctSecret := "correct-secret"
	encodedSecret := base64.StdEncoding.EncodeToString([]byte(correctSecret))

	expectedClient := &models.Client{
		ID:     uuid.MustParse(clientID),
		Secret: encodedSecret,
		Name:   "Test Client",
	}

	mockRepo.On("GetWithID", ctx, clientID).Return(expectedClient, nil)

	// Execute
	client, err := clientService.VerifyClient(ctx, clientID, clientSecret)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.IsType(t, serviceerrors.InvalidClientSecretError{}, err)
	mockRepo.AssertExpectations(t)
}

func TestCheckIfClientExistsByID_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockClientRepository)
	clientService := services.NewClientService(mockRepo)

	clientID := uuid.New().String()
	expectedClient := &models.Client{
		ID:   uuid.MustParse(clientID),
		Name: "Test Client",
	}

	mockRepo.On("GetWithID", ctx, clientID).Return(expectedClient, nil)

	// Execute
	client, err := clientService.CheckIfClientExistsByID(ctx, clientID)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, expectedClient, client)
	mockRepo.AssertExpectations(t)
}

func TestCheckIfClientExistsByID_NotFound(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockClientRepository)
	clientService := services.NewClientService(mockRepo)

	clientID := "non-existent-client"

	mockRepo.On("GetWithID", ctx, clientID).Return(nil, repositories.NewRecordNotFoundError[models.Client](models.Client{}))

	// Execute
	client, err := clientService.CheckIfClientExistsByID(ctx, clientID)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.IsType(t, serviceerrors.ClientNotFoundError{}, err)
	mockRepo.AssertExpectations(t)
}

func TestCheckIfClientExistsByName_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockClientRepository)
	clientService := services.NewClientService(mockRepo)

	clientName := "Test Client"
	expectedClient := &models.Client{
		ID:   uuid.New(),
		Name: clientName,
	}

	mockRepo.On("GetWithName", ctx, clientName).Return(expectedClient, nil)

	// Execute
	client, err := clientService.CheckIfClientExistsByName(ctx, clientName)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, expectedClient, client)
	mockRepo.AssertExpectations(t)
}

func TestCheckIfClientExistsByName_NotFound(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockClientRepository)
	clientService := services.NewClientService(mockRepo)

	clientName := "Non-existent Client"

	mockRepo.On("GetWithName", ctx, clientName).Return(nil, repositories.NewRecordNotFoundError[models.Client](models.Client{}))

	// Execute
	client, err := clientService.CheckIfClientExistsByName(ctx, clientName)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.IsType(t, serviceerrors.ClientNotFoundError{}, err)
	mockRepo.AssertExpectations(t)
}

func TestRegisterClient_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockClientRepository)
	clientService := services.NewClientService(mockRepo)

	mockInput := new(MockClientRegisterInput)
	mockInput.On("GetClientName").Return("Test Client")
	mockInput.On("GetClientEmail").Return("test@example.com")
	mockInput.On("GetRedirectURI").Return("https://example.com/callback")
	mockInput.On("GetResponseTypes").Return("code")
	mockInput.On("GetGrantTypes").Return("authorization_code")
	mockInput.On("GetScopes").Return("read write")

	// Mock UUID generation with a fixed value for testing
	clientUUID := uuid.New()

	// Capture the client being created
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.Client")).Run(func(args mock.Arguments) {
		client := args.Get(1).(*models.Client)
		client.ID = clientUUID // Set the ID to our mock UUID
	}).Return(nil)

	// Execute
	output, err := clientService.RegisterClient(ctx, mockInput)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, clientUUID.String(), output.GetClientID())
	assert.NotEmpty(t, output.GetClientSecret())
	mockRepo.AssertExpectations(t)
	mockInput.AssertExpectations(t)
}

func TestRegisterClient_DatabaseError(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockClientRepository)
	clientService := services.NewClientService(mockRepo)

	mockInput := new(MockClientRegisterInput)
	mockInput.On("GetClientName").Return("Test Client")
	mockInput.On("GetClientEmail").Return("test@example.com")
	mockInput.On("GetRedirectURI").Return("https://example.com/callback")
	mockInput.On("GetResponseTypes").Return("code")
	mockInput.On("GetGrantTypes").Return("authorization_code")
	mockInput.On("GetScopes").Return("read write")

	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.Client")).Return(errors.New("database error"))

	// Execute
	output, err := clientService.RegisterClient(ctx, mockInput)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, output)
	mockRepo.AssertExpectations(t)
	mockInput.AssertExpectations(t)
}
