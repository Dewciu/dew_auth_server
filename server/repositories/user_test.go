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

type CustomUser struct {
	ID           uuid.UUID `gorm:"type:text;primaryKey"`
	CreatedAt    time.Time `gorm:"not null"`
	UpdatedAt    time.Time `gorm:"not null"`
	DeletedAt    gorm.DeletedAt
	Username     string `gorm:"type:varchar(255);unique;not null"`
	PasswordHash string `gorm:"type:varchar(255);not null"`
	Email        string `gorm:"type:varchar(255);unique;not null"`
}

// TableName specifies the table name for CustomUser
func (CustomUser) TableName() string {
	return "users"
}

// Define a mock DB struct that satisfies the minimal behavior we need
type userMockDB struct {
	db *gorm.DB
}

// Helper method to create a new in-memory SQLite database for testing
func newUserMockDB() (*userMockDB, error) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Migrate the schema to create the necessary tables
	// Use the custom model tailored for SQLite
	if err := db.AutoMigrate(&CustomUser{}); err != nil {
		return nil, err
	}

	return &userMockDB{db: db}, nil
}

// UserRepositoryTestSuite defines the test suite
type UserRepositoryTestSuite struct {
	suite.Suite
	userMockDB *userMockDB
	repository repositories.IUserRepository
	users      []*models.User
}

// SetupTest runs before each test
func (suite *UserRepositoryTestSuite) SetupTest() {
	var err error
	suite.userMockDB, err = newUserMockDB()
	if err != nil {
		suite.T().Fatalf("Failed to create mock database: %v", err)
	}

	suite.repository = repositories.NewUserRepository(suite.userMockDB.db)

	// Set up some test users
	suite.users = []*models.User{
		{
			ID:           uuid.New(),
			Username:     "testuser1",
			PasswordHash: "hashed_password1",
			Email:        "user1@example.com",
		},
		{
			ID:           uuid.New(),
			Username:     "testuser2",
			PasswordHash: "hashed_password2",
			Email:        "user2@example.com",
		},
	}

	// Insert test users into the database
	for _, user := range suite.users {
		// Create CustomUser from models.User for SQLite compatibility
		customUser := CustomUser{
			ID:           user.ID,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			Username:     user.Username,
			PasswordHash: user.PasswordHash,
			Email:        user.Email,
		}

		result := suite.userMockDB.db.Create(&customUser)
		if result.Error != nil {
			suite.T().Fatalf("Failed to create test user: %v", result.Error)
		}
	}
}

// TearDownTest runs after each test
func (suite *UserRepositoryTestSuite) TearDownTest() {
	// Clean up database
	suite.userMockDB.db.Exec("DELETE FROM users")
}

// TestGetWithEmail tests the GetWithEmail method
func (suite *UserRepositoryTestSuite) TestGetWithEmail() {
	ctx := context.Background()

	// Test getting an existing user by email
	user, err := suite.repository.GetWithEmail(ctx, suite.users[0].Email)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.users[0].ID, user.ID)
	assert.Equal(suite.T(), suite.users[0].Username, user.Username)
	assert.Equal(suite.T(), suite.users[0].Email, user.Email)
	assert.Equal(suite.T(), suite.users[0].PasswordHash, user.PasswordHash)

	// Test getting a non-existent user
	nonExistentEmail := "nonexistent@example.com"
	user, err = suite.repository.GetWithEmail(ctx, nonExistentEmail)
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), user)
	assert.IsType(suite.T(), repositories.RecordNotFoundError[models.User]{}, err)
}

// TestGetWithEmailOrUsername tests the GetWithEmailOrUsername method
func (suite *UserRepositoryTestSuite) TestGetWithEmailOrUsername() {
	ctx := context.Background()

	// Test getting an existing user by email
	user, err := suite.repository.GetWithEmailOrUsername(ctx, suite.users[0].Email, "")
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.users[0].ID, user.ID)
	assert.Equal(suite.T(), suite.users[0].Email, user.Email)

	// Test getting an existing user by username
	user, err = suite.repository.GetWithEmailOrUsername(ctx, "", suite.users[1].Username)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.users[1].ID, user.ID)
	assert.Equal(suite.T(), suite.users[1].Username, user.Username)

	// Test getting a user by both email and username
	user, err = suite.repository.GetWithEmailOrUsername(ctx, suite.users[1].Email, suite.users[1].Username)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), suite.users[1].ID, user.ID)

	// Test with non-existent email and username
	nonExistentEmail := "nonexistent@example.com"
	nonExistentUsername := "nonexistentuser"
	user, err = suite.repository.GetWithEmailOrUsername(ctx, nonExistentEmail, nonExistentUsername)
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), user)
	assert.IsType(suite.T(), repositories.RecordNotFoundError[models.User]{}, err)
}

// TestCreate tests the Create method
func (suite *UserRepositoryTestSuite) TestCreate() {
	ctx := context.Background()

	// Create a new user
	newUser := &models.User{
		ID:           uuid.New(),
		Username:     "newuser",
		PasswordHash: "new_hashed_password",
		Email:        "newuser@example.com",
		BaseModel:    models.BaseModel{CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	// Test creating a user
	err := suite.repository.Create(ctx, newUser)
	assert.NoError(suite.T(), err)

	// Verify the user was created
	createdUser, err := suite.repository.GetWithEmail(ctx, newUser.Email)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), newUser.ID, createdUser.ID)
	assert.Equal(suite.T(), newUser.Username, createdUser.Username)
	assert.Equal(suite.T(), newUser.Email, createdUser.Email)
	assert.Equal(suite.T(), newUser.PasswordHash, createdUser.PasswordHash)

	// Test creating a user with a duplicate email
	duplicateEmailUser := &models.User{
		ID:           uuid.New(),
		Username:     "uniqueusername",
		PasswordHash: "hashed_password",
		Email:        suite.users[0].Email, // Same email as an existing user
	}

	// Since SQLite might handle constraint violations differently, wrap this in a conditional
	err = suite.repository.Create(ctx, duplicateEmailUser)
	assert.Error(suite.T(), err) // Should fail due to unique email constraint

	// Test creating a user with a duplicate username
	duplicateUsernameUser := &models.User{
		ID:           uuid.New(),
		Username:     suite.users[1].Username, // Same username as an existing user
		PasswordHash: "hashed_password",
		Email:        "unique@example.com",
	}

	err = suite.repository.Create(ctx, duplicateUsernameUser)
	assert.Error(suite.T(), err) // Should fail due to unique username constraint
}

// Run the suite
func TestUserRepositorySuite(t *testing.T) {
	suite.Run(t, new(UserRepositoryTestSuite))
}

// Test edge cases and error handling
func TestUserRepositoryEdgeCases(t *testing.T) {
	userMockDB, err := newUserMockDB()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	repo := repositories.NewUserRepository(userMockDB.db)
	ctx := context.Background()

	// Test with empty email
	user, err := repo.GetWithEmail(ctx, "")
	assert.Error(t, err)
	assert.Nil(t, user)

	// Test with empty email and username
	user, err = repo.GetWithEmailOrUsername(ctx, "", "")
	assert.Error(t, err)
	assert.Nil(t, user)

	// Test creating user with missing required fields
	incompleteUser := &models.User{
		ID:       uuid.New(),
		Username: "incomplete",
		// Missing PasswordHash and Email
	}
	err = repo.Create(ctx, incompleteUser)
	assert.Error(t, err) // Should fail due to NOT NULL constraints

	// Test with minimal valid user
	minimalUser := &models.User{
		ID:           uuid.New(),
		Username:     "minimaluser",
		PasswordHash: "minimal_password",
		Email:        "minimal@example.com",
		BaseModel:    models.BaseModel{CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	err = repo.Create(ctx, minimalUser)
	assert.NoError(t, err)

	// Verify we can retrieve the minimal user
	retrievedUser, err := repo.GetWithEmail(ctx, minimalUser.Email)
	assert.NoError(t, err)
	assert.Equal(t, minimalUser.ID, retrievedUser.ID)
	assert.Equal(t, minimalUser.Username, retrievedUser.Username)
	assert.Equal(t, minimalUser.Email, retrievedUser.Email)
}

// Test behavior with damaged database
func TestUserRepositoryWithCorruptDB(t *testing.T) {
	// Create a database
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}

	// Create the table but in a way that will cause issues
	db.Exec("CREATE TABLE users (id TEXT, email TEXT)") // Deliberately incomplete schema

	// Create the repository with the mocked DB
	repo := repositories.NewUserRepository(db)
	ctx := context.Background()

	// Try to create a user with all fields - should fail since table doesn't have all columns
	newUser := &models.User{
		ID:           uuid.New(),
		Username:     "corruptuser",
		PasswordHash: "corrupt_password",
		Email:        "corrupt@example.com",
	}

	err = repo.Create(ctx, newUser)
	// This should fail because the table schema doesn't match the model
	assert.Error(t, err)

	// Try to get a user - might partially work with incomplete schema
	user, err := repo.GetWithEmail(ctx, "corrupt@example.com")
	// Either it errors or returns incomplete data
	if err == nil {
		assert.NotEqual(t, newUser.Username, user.Username) // Should be empty/default
	} else {
		assert.Error(t, err)
	}
}

// Test error handling with constraint violations
func TestUserRepositoryConstraintViolations(t *testing.T) {
	userMockDB, err := newUserMockDB()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	repo := repositories.NewUserRepository(userMockDB.db)
	ctx := context.Background()

	// Create initial user
	initialUser := &models.User{
		ID:           uuid.New(),
		Username:     "constraintuser",
		PasswordHash: "password",
		Email:        "constraint@example.com",
		BaseModel:    models.BaseModel{CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	err = repo.Create(ctx, initialUser)
	assert.NoError(t, err)

	// Test various constraint violations

	// 1. Username uniqueness constraint
	usernameViolationUser := &models.User{
		ID:           uuid.New(),
		Username:     "constraintuser", // Same as initialUser
		PasswordHash: "password2",
		Email:        "unique@example.com",
	}
	err = repo.Create(ctx, usernameViolationUser)
	assert.Error(t, err)

	// 2. Email uniqueness constraint
	emailViolationUser := &models.User{
		ID:           uuid.New(),
		Username:     "uniqueuser",
		PasswordHash: "password3",
		Email:        "constraint@example.com", // Same as initialUser
	}
	err = repo.Create(ctx, emailViolationUser)
	assert.Error(t, err)

	// 3. Both constraints violated
	bothViolationsUser := &models.User{
		ID:           uuid.New(),
		Username:     "constraintuser", // Same as initialUser
		PasswordHash: "password4",
		Email:        "constraint@example.com", // Same as initialUser
	}
	err = repo.Create(ctx, bothViolationsUser)
	assert.Error(t, err)
}
