package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// MockUserRepository is a mock implementation of the IUserRepository interface
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetWithEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetWithEmailOrUsername(ctx context.Context, email string, username string) (*models.User, error) {
	args := m.Called(ctx, email, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func TestRegisterUser_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userInput := &inputs.UserRegisterInput{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "securepassword123",
	}

	// Mock that the user doesn't exist yet
	mockRepo.On("GetWithEmailOrUsername", ctx, userInput.Email, userInput.Username).Return(nil,
		repositories.NewRecordNotFoundError(models.User{}))

	// Capture the user being created
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.User")).Run(func(args mock.Arguments) {
		user := args.Get(1).(*models.User)
		assert.Equal(t, userInput.Username, user.Username)
		assert.Equal(t, userInput.Email, user.Email)
		// Verify password is hashed
		assert.NotEqual(t, userInput.Password, user.PasswordHash)
		err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(userInput.Password))
		assert.NoError(t, err)
	}).Return(nil)

	// Execute
	err := userService.RegisterUser(ctx, userInput)

	// Verify
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestRegisterUser_UserAlreadyExists(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userInput := &inputs.UserRegisterInput{
		Username: "existinguser",
		Email:    "existing@example.com",
		Password: "securepassword123",
	}

	existingUser := &models.User{
		ID:       uuid.New(),
		Username: userInput.Username,
		Email:    userInput.Email,
	}

	// Mock that the user already exists
	mockRepo.On("GetWithEmailOrUsername", ctx, userInput.Email, userInput.Username).Return(existingUser, nil)

	// Execute
	err := userService.RegisterUser(ctx, userInput)

	// Verify
	assert.Error(t, err)
	assert.IsType(t, serviceerrors.UserAlreadyExistsError{}, err)
	mockRepo.AssertExpectations(t)
}

func TestRegisterUser_DatabaseError(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	userInput := &inputs.UserRegisterInput{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "securepassword123",
	}

	// Mock repository errors
	mockRepo.On("GetWithEmailOrUsername", ctx, userInput.Email, userInput.Username).Return(nil, errors.New("database error"))

	// Execute
	err := userService.RegisterUser(ctx, userInput)

	// Verify
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not get user from database")
	mockRepo.AssertExpectations(t)
}

func TestLoginUser_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	loginInput := inputs.UserLoginInput{
		Email:    "test@example.com",
		Password: "securepassword123",
	}

	// Create a hashed password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(loginInput.Password), 14)

	expectedUser := &models.User{
		ID:           uuid.New(),
		Username:     "testuser",
		Email:        loginInput.Email,
		PasswordHash: string(hashedPassword),
	}

	mockRepo.On("GetWithEmail", ctx, loginInput.Email).Return(expectedUser, nil)

	// Execute
	user, err := userService.LoginUser(ctx, loginInput)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, user)
	mockRepo.AssertExpectations(t)
}

func TestLoginUser_UserDoesNotExist(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	loginInput := inputs.UserLoginInput{
		Email:    "nonexistent@example.com",
		Password: "securepassword123",
	}

	mockRepo.On("GetWithEmail", ctx, loginInput.Email).Return(nil,
		repositories.NewRecordNotFoundError[models.User](models.User{}))

	// Execute
	user, err := userService.LoginUser(ctx, loginInput)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.IsType(t, serviceerrors.UserDoesNotExistError{}, err)
	mockRepo.AssertExpectations(t)
}

func TestLoginUser_WrongPassword(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	loginInput := inputs.UserLoginInput{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	// Create a hashed password for a different password
	correctPassword := "correctpassword"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(correctPassword), 14)

	storedUser := &models.User{
		ID:           uuid.New(),
		Username:     "testuser",
		Email:        loginInput.Email,
		PasswordHash: string(hashedPassword),
	}

	mockRepo.On("GetWithEmail", ctx, loginInput.Email).Return(storedUser, nil)

	// Execute
	user, err := userService.LoginUser(ctx, loginInput)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.IsType(t, serviceerrors.InvalidUserPasswordError{}, err)
	mockRepo.AssertExpectations(t)
}

func TestLoginUser_DatabaseError(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockRepo := new(MockUserRepository)
	userService := services.NewUserService(mockRepo)

	loginInput := inputs.UserLoginInput{
		Email:    "test@example.com",
		Password: "securepassword123",
	}

	mockRepo.On("GetWithEmail", ctx, loginInput.Email).Return(nil, errors.New("database error"))

	// Execute
	user, err := userService.LoginUser(ctx, loginInput)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "could not get user with e-mail")
	mockRepo.AssertExpectations(t)
}
