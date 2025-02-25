package repositories

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/models"
	"gorm.io/gorm"
)

var _ IUserRepository = new(UserRepository)

type IUserRepository interface {
	GetWithEmail(ctx context.Context, email string) (*models.User, error)
	GetWithEmailOrUsername(ctx context.Context, email string, name string) (*models.User, error)
	Create(ctx context.Context, user *models.User) error
}

type UserRepository struct {
	database *gorm.DB
}

func NewUserRepository(database *gorm.DB) IUserRepository {
	return &UserRepository{
		database: database,
	}
}

func (r *UserRepository) GetWithEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	result := r.database.Where("email = ?", email).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, result.Error
}

func (r *UserRepository) GetWithEmailOrUsername(ctx context.Context, email string, username string) (*models.User, error) {
	var user models.User
	result := r.database.Where("email = ?", email).Or("username = ?", username).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, result.Error
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	result := r.database.WithContext(ctx).Create(user)
	return result.Error
}
