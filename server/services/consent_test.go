package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockConsentRepository is a mock implementation of the IConsentRepository interface
type MockConsentRepository struct {
	mock.Mock
}

func (m *MockConsentRepository) GetForClientAndUser(ctx context.Context, clientID uuid.UUID, userID uuid.UUID) (*models.Consent, error) {
	args := m.Called(ctx, clientID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Consent), args.Error(1)
}

func (m *MockConsentRepository) Create(ctx context.Context, consent *models.Consent) error {
	args := m.Called(ctx, consent)
	return args.Error(0)
}

func TestConsentForClientAndUserExists_Exists(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockConsentRepository)
	consentService := services.NewConsentService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()

	clientUUID := uuid.MustParse(clientID)
	userUUID := uuid.MustParse(userID)

	// Create existing consent
	existingConsent := &models.Consent{
		ClientID:  clientUUID,
		UserID:    userUUID,
		Scopes:    "read write",
		GrantedAt: time.Now(),
	}

	mockRepo.On("GetForClientAndUser", ctx, clientUUID, userUUID).Return(existingConsent, nil)

	// Execute
	exists, err := consentService.ConsentForClientAndUserExists(ctx, clientID, userID)

	// Verify
	assert.NoError(t, err)
	assert.True(t, exists)
	mockRepo.AssertExpectations(t)
}

func TestConsentForClientAndUserExists_NotExists(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockConsentRepository)
	consentService := services.NewConsentService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()

	clientUUID := uuid.MustParse(clientID)
	userUUID := uuid.MustParse(userID)

	// No consent exists
	mockRepo.On("GetForClientAndUser", ctx, clientUUID, userUUID).Return(nil,
		repositories.NewRecordNotFoundError(models.Consent{}))

	// Execute
	exists, err := consentService.ConsentForClientAndUserExists(ctx, clientID, userID)

	// Verify
	assert.Error(t, err)
	assert.False(t, exists)
	mockRepo.AssertExpectations(t)
}

func TestConsentForClientAndUserExists_Error(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockConsentRepository)
	consentService := services.NewConsentService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()

	clientUUID := uuid.MustParse(clientID)
	userUUID := uuid.MustParse(userID)

	// Repository error
	mockRepo.On("GetForClientAndUser", ctx, clientUUID, userUUID).Return(nil, errors.New("database error"))

	// Execute
	exists, err := consentService.ConsentForClientAndUserExists(ctx, clientID, userID)

	// Verify
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "database error")
	mockRepo.AssertExpectations(t)
}

func TestGrantConsentForClientAndUser_NewConsent(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockConsentRepository)
	consentService := services.NewConsentService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()
	scopes := "read write"

	clientUUID := uuid.MustParse(clientID)
	userUUID := uuid.MustParse(userID)

	// No existing consent
	mockRepo.On("GetForClientAndUser", ctx, clientUUID, userUUID).Return(nil,
		repositories.NewRecordNotFoundError(models.Consent{}))

	// Expect consent creation
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.Consent")).Run(func(args mock.Arguments) {
		consent := args.Get(1).(*models.Consent)
		assert.Equal(t, clientUUID, consent.ClientID)
		assert.Equal(t, userUUID, consent.UserID)
		assert.Equal(t, scopes, consent.Scopes)
		assert.NotZero(t, consent.GrantedAt)
	}).Return(nil)

	// Execute
	consent, err := consentService.GrantConsentForClientAndUser(ctx, clientID, userID, scopes)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, consent)
	assert.Equal(t, clientUUID, consent.ClientID)
	assert.Equal(t, userUUID, consent.UserID)
	assert.Equal(t, scopes, consent.Scopes)
	mockRepo.AssertExpectations(t)
}

func TestGrantConsentForClientAndUser_ExistingConsent(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockConsentRepository)
	consentService := services.NewConsentService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()
	scopes := "read write"

	clientUUID := uuid.MustParse(clientID)
	userUUID := uuid.MustParse(userID)

	// Existing consent
	existingConsent := &models.Consent{
		ClientID:  clientUUID,
		UserID:    userUUID,
		Scopes:    scopes,
		GrantedAt: time.Now().Add(-24 * time.Hour), // Granted yesterday
	}

	mockRepo.On("GetForClientAndUser", ctx, clientUUID, userUUID).Return(existingConsent, nil)

	// Execute
	consent, err := consentService.GrantConsentForClientAndUser(ctx, clientID, userID, scopes)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, existingConsent, consent)
	mockRepo.AssertExpectations(t)
}

func TestGrantConsentForClientAndUser_RepositoryError(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockConsentRepository)
	consentService := services.NewConsentService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()
	scopes := "read write"

	clientUUID := uuid.MustParse(clientID)
	userUUID := uuid.MustParse(userID)

	// Error when checking for existing consent
	mockRepo.On("GetForClientAndUser", ctx, clientUUID, userUUID).Return(nil, errors.New("database error"))

	// Execute
	consent, err := consentService.GrantConsentForClientAndUser(ctx, clientID, userID, scopes)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, consent)
	assert.Contains(t, err.Error(), "consent check error")
	mockRepo.AssertExpectations(t)
}

func TestGrantConsentForClientAndUser_GetConsentError(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockConsentRepository)
	consentService := services.NewConsentService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()
	scopes := "read write"

	clientUUID := uuid.MustParse(clientID)
	userUUID := uuid.MustParse(userID)

	// No existing consent
	mockRepo.On("GetForClientAndUser", ctx, clientUUID, userUUID).Return(nil,
		errors.New("consent retrieve error"))

	// Execute
	consent, err := consentService.GrantConsentForClientAndUser(ctx, clientID, userID, scopes)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, consent)
	assert.Contains(t, err.Error(), "consent check error")
	mockRepo.AssertExpectations(t)
}

func TestGrantConsentForClientAndUser_ConsentCreateError(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockConsentRepository)
	consentService := services.NewConsentService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()
	scopes := "read write"

	clientUUID := uuid.MustParse(clientID)
	userUUID := uuid.MustParse(userID)

	mockRepo.On("GetForClientAndUser", ctx, clientUUID, userUUID).Return(nil,
		repositories.NewRecordNotFoundError(models.Consent{}))

	// No existing consent
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.Consent")).Return(errors.New("create error"))

	// Execute
	consent, err := consentService.GrantConsentForClientAndUser(ctx, clientID, userID, scopes)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, consent)
	assert.Contains(t, err.Error(), "creation error")
	mockRepo.AssertExpectations(t)
}

func TestRevokeConsentForClientAndUser(t *testing.T) {
	t.Parallel()
	// Setup
	ctx := context.Background()
	mockRepo := new(MockConsentRepository)
	consentService := services.NewConsentService(mockRepo)

	clientID := uuid.New().String()
	userID := uuid.New().String()

	// This is intentionally empty as the function is a stub in the implementation
	// Execute
	err := consentService.RevokeConsentForClientAndUser(ctx, clientID, userID)

	// Verify
	assert.NoError(t, err) // Should return nil as it's a stub
}
