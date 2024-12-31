package services

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
)

var _ IUserService = new(UserService)

type IUserService interface {
	CheckIfUserExistsByID(ctx context.Context, userID string) (*models.User, error)
}

type UserService struct {
	userRepository repositories.IUserRepository
}

func NewUserService(userRepository repositories.IUserRepository) UserService {
	return UserService{
		userRepository: userRepository,
	}
}

func (s *UserService) CheckIfUserExistsByID(
	ctx context.Context,
	userID string,
) (*models.User, error) {
	user, err := s.userRepository.GetWithID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	return user, nil
}
