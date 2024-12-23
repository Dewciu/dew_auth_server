package repositories

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
	"gorm.io/gorm"
)

var _ IUserRepository = new(UserRepository)

type IUserRepository interface {
	GetWithID(ctx context.Context, id string) (*models.User, error)
	GetWithName(ctx context.Context, name string) (*models.User, error)
	GetWithEmail(ctx context.Context, email string) (*models.User, error)
	Create(ctx context.Context, user *models.User) error
	DeleteWithID(ctx context.Context, id string) error
	Update(ctx context.Context, user *models.User) error
}

type UserRepository struct {
	database *gorm.DB
}

func NewUserRepository(database *gorm.DB) IUserRepository {
	return &UserRepository{
		database: database,
	}
}

func (r *UserRepository) GetWithID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	result := r.database.Where("id = ?", id).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

func (r *UserRepository) GetWithName(ctx context.Context, name string) (*models.User, error) {
	var user models.User
	result := r.database.Where("name = ?", name).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

func (r *UserRepository) GetWithEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	result := r.database.Where("email = ?", email).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	result := r.database.WithContext(ctx).Create(user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *UserRepository) DeleteWithID(ctx context.Context, id string) error {
	result := r.database.WithContext(ctx).Where("id = ?", id).Delete(&models.User{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	result := r.database.WithContext(ctx).Save(user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}
