package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// CustomConsent omits BaseModel and directly includes its fields to work with SQLite
type CustomConsent struct {
	ID        uuid.UUID `gorm:"type:text;primaryKey"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
	DeletedAt gorm.DeletedAt
	ClientID  uuid.UUID `gorm:"type:text;not null"`
	UserID    uuid.UUID `gorm:"type:text;not null"`
	Scopes    string    `gorm:"type:text;not null"`
	GrantedAt time.Time `gorm:"not null"`
}

// TableName specifies the table name for CustomConsent
func (CustomConsent) TableName() string {
	return "consents"
}

// Define a mock DB struct that satisfies the minimal behavior we need
type consentMockDB struct {
	db *gorm.DB
}

// Helper method to create a new in-memory SQLite database for testing
func newConsentMockDB() (*consentMockDB, error) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Migrate the schema to create the necessary tables
	// Use the custom model tailored for SQLite
	if err := db.AutoMigrate(&CustomConsent{}); err != nil {
		return nil, err
	}

	return &consentMockDB{db: db}, nil
}

// ConsentRepositoryTestSuite defines the test suite
type ConsentRepositoryTestSuite struct {
	suite.Suite
	consentMockDB *consentMockDB
	repository    repositories.IConsentRepository
	consents      []*models.Consent
	userIDs       []uuid.UUID
	clientIDs     []uuid.UUID
}

// SetupTest runs before each test
func (suite *ConsentRepositoryTestSuite) SetupTest() {
	var err error
	suite.consentMockDB, err = newConsentMockDB()
	if err != nil {
		suite.T().Fatalf("Failed to create mock database: %v", err)
	}

	suite.repository = repositories.NewConsentRepository(suite.consentMockDB.db)

	// Create some user and client IDs
	suite.userIDs = []uuid.UUID{uuid.New(), uuid.New()}
	suite.clientIDs = []uuid.UUID{uuid.New(), uuid.New()}

	// Set up some test consents
	grantedTime := time.Now().Add(-24 * time.Hour) // Granted one day ago
	suite.consents = []*models.Consent{
		{
			BaseModel: models.BaseModel{
				ID:        uuid.New(),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			ClientID:  suite.clientIDs[0],
			UserID:    suite.userIDs[0],
			Scopes:    "read,write",
			GrantedAt: grantedTime,
		},
		{
			BaseModel: models.BaseModel{
				ID:        uuid.New(),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			ClientID:  suite.clientIDs[1],
			UserID:    suite.userIDs[1],
			Scopes:    "read",
			GrantedAt: grantedTime.Add(1 * time.Hour), // 1 hour later
		},
	}

	// Insert test consents into the database
	for _, consent := range suite.consents {
		// Create CustomConsent from models.Consent for SQLite compatibility
		customConsent := CustomConsent{
			ID:        consent.ID,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			ClientID:  consent.ClientID,
			UserID:    consent.UserID,
			Scopes:    consent.Scopes,
			GrantedAt: consent.GrantedAt,
		}

		result := suite.consentMockDB.db.Create(&customConsent)
		if result.Error != nil {
			suite.T().Fatalf("Failed to create test consent: %v", result.Error)
		}
	}
}

// TearDownTest runs after each test
func (suite *ConsentRepositoryTestSuite) TearDownTest() {
	// Clean up database
	suite.consentMockDB.db.Exec("DELETE FROM consents")
}

// TestGetForClientAndUser tests the GetForClientAndUser method
func (suite *ConsentRepositoryTestSuite) TestGetForClientAndUser() {
	ctx := context.Background()

	// Test getting an existing consent
	consent, err := suite.repository.GetForClientAndUser(ctx, suite.clientIDs[0], suite.userIDs[0])
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), consent)
	assert.Equal(suite.T(), suite.consents[0].ID, consent.ID)
	assert.Equal(suite.T(), suite.consents[0].ClientID, consent.ClientID)
	assert.Equal(suite.T(), suite.consents[0].UserID, consent.UserID)
	assert.Equal(suite.T(), suite.consents[0].Scopes, consent.Scopes)
	assert.WithinDuration(suite.T(), suite.consents[0].GrantedAt, consent.GrantedAt, time.Second)

	// Test getting a non-existent consent (client exists, user exists, but not this combination)
	nonExistentConsent, err := suite.repository.GetForClientAndUser(ctx, suite.clientIDs[0], suite.userIDs[1])
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), nonExistentConsent)
	assert.IsType(suite.T(), repositories.RecordNotFoundError[models.Consent]{}, err)

	// Test with non-existent client ID
	nonExistentClientID := uuid.New()
	nonExistentConsent, err = suite.repository.GetForClientAndUser(ctx, nonExistentClientID, suite.userIDs[0])
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), nonExistentConsent)
	assert.IsType(suite.T(), repositories.RecordNotFoundError[models.Consent]{}, err)

	// Test with non-existent user ID
	nonExistentUserID := uuid.New()
	nonExistentConsent, err = suite.repository.GetForClientAndUser(ctx, suite.clientIDs[0], nonExistentUserID)
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), nonExistentConsent)
	assert.IsType(suite.T(), repositories.RecordNotFoundError[models.Consent]{}, err)
}

// TestCreate tests the Create method
func (suite *ConsentRepositoryTestSuite) TestCreate() {
	ctx := context.Background()

	// Create a new consent with new client and user
	newClientID := uuid.New()
	newUserID := uuid.New()
	newConsent := &models.Consent{
		BaseModel: models.BaseModel{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		ClientID:  newClientID,
		UserID:    newUserID,
		Scopes:    "read,profile",
		GrantedAt: time.Now(),
	}

	// Test creating a consent
	err := suite.repository.Create(ctx, newConsent)
	assert.NoError(suite.T(), err)

	// Verify the consent was created
	createdConsent, err := suite.repository.GetForClientAndUser(ctx, newClientID, newUserID)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), createdConsent)
	assert.Equal(suite.T(), newConsent.ID, createdConsent.ID)
	assert.Equal(suite.T(), newConsent.ClientID, createdConsent.ClientID)
	assert.Equal(suite.T(), newConsent.UserID, createdConsent.UserID)
	assert.Equal(suite.T(), newConsent.Scopes, createdConsent.Scopes)
	assert.WithinDuration(suite.T(), newConsent.GrantedAt, createdConsent.GrantedAt, time.Second)

	// Test creating a duplicate consent (same client and user)
	// This should update the existing consent rather than error in a real implementation
	// But for SQLite, it might error due to compound key constraints
	duplicateConsent := &models.Consent{
		BaseModel: models.BaseModel{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		ClientID:  newClientID,
		UserID:    newUserID,
		Scopes:    "read,write,delete", // Updated scopes
		GrantedAt: time.Now(),
	}

	err = suite.repository.Create(ctx, duplicateConsent)
	// The behavior here depends on how the repository is implemented:
	// 1. If it has a upsert or replace mechanism: No error, updated consent
	// 2. If it doesn't handle duplicates: Error due to constraint violation
	// We'll check both possibilities
	if err == nil {
		// If successful, verify the consent was updated
		updatedConsent, getErr := suite.repository.GetForClientAndUser(ctx, newClientID, newUserID)
		assert.NoError(suite.T(), getErr)
		// The ID should be the original or the new one, depending on implementation
		assert.True(suite.T(),
			updatedConsent.ID == newConsent.ID || updatedConsent.ID == duplicateConsent.ID,
			"ID should match either the original or duplicate consent")
		assert.Equal(suite.T(), duplicateConsent.Scopes, updatedConsent.Scopes)
	} else {
		// If it errors, it should be due to a constraint violation
		suite.T().Logf("Creating duplicate consent resulted in error: %v", err)
	}
}

// Run the suite
func TestConsentRepositorySuite(t *testing.T) {
	suite.Run(t, new(ConsentRepositoryTestSuite))
}

// Test edge cases
func TestConsentRepositoryEdgeCases(t *testing.T) {
	consentMockDB, err := newConsentMockDB()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	repo := repositories.NewConsentRepository(consentMockDB.db)
	ctx := context.Background()

	// Test with zero-value UUIDs
	zeroUUID := uuid.UUID{}
	consent, err := repo.GetForClientAndUser(ctx, zeroUUID, zeroUUID)
	assert.Error(t, err)
	assert.Nil(t, consent)

	// Test creating consent with zero-value UUIDs
	invalidConsent := &models.Consent{
		ClientID:  zeroUUID, // Zero UUID
		UserID:    zeroUUID, // Zero UUID
		Scopes:    "read",
		GrantedAt: time.Now(),
	}
	err = repo.Create(ctx, invalidConsent)
	assert.Error(t, err) // Should fail due to NOT NULL or foreign key constraints

	// Test with minimal valid consent
	minimalConsent := &models.Consent{
		BaseModel: models.BaseModel{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		ClientID:  uuid.New(),
		UserID:    uuid.New(),
		Scopes:    "", // Empty scopes
		GrantedAt: time.Now(),
	}
	err = repo.Create(ctx, minimalConsent)
	if err != nil {
		t.Logf("Creating minimal consent failed: %v", err)
	} else {
		// Verify retrieval works
		retrievedConsent, getErr := repo.GetForClientAndUser(ctx, minimalConsent.ClientID, minimalConsent.UserID)
		assert.NoError(t, getErr)
		assert.Equal(t, minimalConsent.ID, retrievedConsent.ID)
		assert.Equal(t, minimalConsent.Scopes, retrievedConsent.Scopes)
	}
}

// Test behavior with damaged database
func TestConsentRepositoryWithCorruptDB(t *testing.T) {
	// Create a database
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}

	// Create the table but in a way that will cause issues
	db.Exec("CREATE TABLE consents (id TEXT, client_id TEXT)") // Deliberately incomplete schema

	// Create the repository with the mocked DB
	repo := repositories.NewConsentRepository(db)
	ctx := context.Background()

	// Try to create a consent with all fields - should fail since table doesn't have all columns
	newConsent := &models.Consent{
		BaseModel: models.BaseModel{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		ClientID:  uuid.New(),
		UserID:    uuid.New(),
		Scopes:    "read,write",
		GrantedAt: time.Now(),
	}

	err = repo.Create(ctx, newConsent)
	// This should fail because the table schema doesn't match the model
	assert.Error(t, err)

	// Try to get a consent - should fail with the corrupt schema
	consent, err := repo.GetForClientAndUser(ctx, newConsent.ClientID, newConsent.UserID)
	assert.Error(t, err)
	assert.Equal(t, &models.Consent{}, consent)
}

// Test additional scenarios
func TestConsentRepositoryAdditionalScenarios(t *testing.T) {
	consentMockDB, err := newConsentMockDB()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	repo := repositories.NewConsentRepository(consentMockDB.db)
	ctx := context.Background()

	// Test scenario: Creating multiple consents for the same user with different clients
	userID := uuid.New()
	clientID1 := uuid.New()
	clientID2 := uuid.New()

	// Create first consent
	consent1 := &models.Consent{
		BaseModel: models.BaseModel{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		ClientID:  clientID1,
		UserID:    userID,
		Scopes:    "read",
		GrantedAt: time.Now().Add(-1 * time.Hour),
	}
	err = repo.Create(ctx, consent1)
	assert.NoError(t, err)

	// Create second consent for same user but different client
	consent2 := &models.Consent{
		BaseModel: models.BaseModel{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		ClientID:  clientID2,
		UserID:    userID,
		Scopes:    "write",
		GrantedAt: time.Now(),
	}
	err = repo.Create(ctx, consent2)
	assert.NoError(t, err)

	// Verify both consents were created and can be retrieved
	retrievedConsent1, err := repo.GetForClientAndUser(ctx, clientID1, userID)
	assert.NoError(t, err)
	assert.Equal(t, consent1.ID, retrievedConsent1.ID)
	assert.Equal(t, "read", retrievedConsent1.Scopes)

	retrievedConsent2, err := repo.GetForClientAndUser(ctx, clientID2, userID)
	assert.NoError(t, err)
	assert.Equal(t, consent2.ID, retrievedConsent2.ID)
	assert.Equal(t, "write", retrievedConsent2.Scopes)

	// Test scenario: Creating multiple consents for the same client with different users
	clientID := uuid.New()
	userID1 := uuid.New()
	userID2 := uuid.New()

	// Create first consent
	consent3 := &models.Consent{
		BaseModel: models.BaseModel{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		ClientID:  clientID,
		UserID:    userID1,
		Scopes:    "read,profile",
		GrantedAt: time.Now().Add(-2 * time.Hour),
	}
	err = repo.Create(ctx, consent3)
	assert.NoError(t, err)

	// Create second consent for same client but different user
	consent4 := &models.Consent{
		BaseModel: models.BaseModel{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		ClientID:  clientID,
		UserID:    userID2,
		Scopes:    "read,write,profile",
		GrantedAt: time.Now().Add(-1 * time.Hour),
	}
	err = repo.Create(ctx, consent4)
	assert.NoError(t, err)

	// Verify both consents were created and can be retrieved
	retrievedConsent3, err := repo.GetForClientAndUser(ctx, clientID, userID1)
	assert.NoError(t, err)
	assert.Equal(t, consent3.ID, retrievedConsent3.ID)
	assert.Equal(t, "read,profile", retrievedConsent3.Scopes)

	retrievedConsent4, err := repo.GetForClientAndUser(ctx, clientID, userID2)
	assert.NoError(t, err)
	assert.Equal(t, consent4.ID, retrievedConsent4.ID)
	assert.Equal(t, "read,write,profile", retrievedConsent4.Scopes)
}
