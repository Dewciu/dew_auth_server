package repositories

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
	"gorm.io/gorm"
)

var _ IAccessTokenRepository = new(AccessTokenRepository)

type IAccessTokenRepository interface {
	GetWithID(ctx context.Context, id string) (*models.AccessToken, error)
}

type AccessTokenRepository struct {
	database *gorm.DB
}

func NewAccessTokenRepository(database *gorm.DB) AccessTokenRepository {
	return AccessTokenRepository{
		database: database,
	}
}

func (r *AccessTokenRepository) GetWithID(ctx context.Context, id string) (*models.AccessToken, error) {
	var accessToken models.AccessToken
	result := r.database.Where("id = ?", id).First(&accessToken)
	if result.Error != nil {
		return nil, result.Error
	}

	return &accessToken, nil
}
