package services

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/dewciu/dew_auth_server/server/utils"
)

var _ IUserService = new(UserService)

type IUserService interface {
	RegisterUser(ctx context.Context, userInput *inputs.UserRegisterInput) error
}

type UserService struct {
	userRepository repositories.IUserRepository
}

func NewUserService(userRepository repositories.IUserRepository) IUserService {
	return &UserService{
		userRepository: userRepository,
	}
}

func (s *UserService) RegisterUser(
	ctx context.Context,
	userInput *inputs.UserRegisterInput,
) error {
	user, err := s.userRepository.GetWithEmailOrUsername(ctx, userInput.Email, userInput.Username)
	if err != nil {
		return errors.New("an error occurred")
	}

	if user != nil {
		return errors.New("user already exists")
	}

	hashedPw, err := utils.HashPassword(userInput.Password)

	if err != nil {
		return errors.New("could not hash password")
	}

	userToCreate := models.User{
		Username:     userInput.Username,
		Email:        userInput.Email,
		PasswordHash: hashedPw,
	}

	err = s.userRepository.Create(ctx, &userToCreate)

	if err != nil {
		return errors.New("could not create user")
	}

	return nil
}
