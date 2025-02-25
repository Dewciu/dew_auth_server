package services

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/dewciu/dew_auth_server/server/utils"
	"github.com/sirupsen/logrus"
)

var _ IUserService = new(UserService)

type IUserService interface {
	RegisterUser(ctx context.Context, userInput *inputs.UserRegisterInput) error
	LoginUser(ctx context.Context, userLoginInput inputs.UserLoginInput) (*models.User, error)
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

func (s *UserService) LoginUser(
	ctx context.Context,
	userLoginInput inputs.UserLoginInput,
) (*models.User, error) {
	user, err := s.userRepository.GetWithEmail(ctx, userLoginInput.Email)
	if err != nil {
		if errors.As(err, &repositories.RecordNotFoundError[models.User]{}) {
			e := serviceerrors.NewUserDoesNotExistError(userLoginInput.Email)
			logrus.Debug(e)
			return nil, e
		}

		errMsg := "could not get user with e-mail " + userLoginInput.Email
		logrus.WithError(err).Error(errMsg)
		return nil, errors.New(errMsg)
	}

	if !utils.VerifyPassword(userLoginInput.Password, user.PasswordHash) {
		e := serviceerrors.NewInvalidUserPasswordError(userLoginInput.Email)
		logrus.WithError(err).Debug(e)
		return nil, e
	}

	return user, nil
}
