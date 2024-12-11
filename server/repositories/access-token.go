package repositories

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
	"gorm.io/gorm"
)

var _ IAccessTokenRepository = new(AccessTokenRepository)

type IAccessTokenRepository interface {
	GetWithID(ctx context.Context, id string) (*models.AccessToken, error)
	Create(ctx context.Context, accessToken *models.AccessToken) error
	Update(ctx context.Context, accessToken *models.AccessToken) error
	GetByToken(ctx context.Context, token string) (*models.AccessToken, error)
	GetByUserID(ctx context.Context, userID string) ([]models.AccessToken, error)
	GetByClientID(ctx context.Context, clientID string) ([]models.AccessToken, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*models.AccessToken, error)
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

func (r *AccessTokenRepository) Create(ctx context.Context, accessToken *models.AccessToken) error {
	result := r.database.WithContext(ctx).Create(accessToken)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *AccessTokenRepository) Update(ctx context.Context, accessToken *models.AccessToken) error {
	result := r.database.WithContext(ctx).Save(accessToken)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *AccessTokenRepository) GetByToken(ctx context.Context, token string) (*models.AccessToken, error) {
	var accessToken models.AccessToken
	result := r.database.WithContext(ctx).Where("token = ?", token).First(&accessToken)
	if result.Error != nil {
		return nil, result.Error
	}
	return &accessToken, nil
}

func (r *AccessTokenRepository) GetByUserID(ctx context.Context, userID string) ([]models.AccessToken, error) {
	var accessTokens []models.AccessToken
	result := r.database.WithContext(ctx).Where("user_id = ?", userID).Find(&accessTokens)
	if result.Error != nil {
		return nil, result.Error
	}
	return accessTokens, nil
}

func (r *AccessTokenRepository) GetByClientID(ctx context.Context, clientID string) ([]models.AccessToken, error) {
	var accessTokens []models.AccessToken
	result := r.database.WithContext(ctx).Where("client_id = ?", clientID).Find(&accessTokens)
	if result.Error != nil {
		return nil, result.Error
	}
	return accessTokens, nil
}

func (r *AccessTokenRepository) GetByRefreshToken(ctx context.Context, refreshToken string) (*models.AccessToken, error) {
	var accessToken models.AccessToken
	result := r.database.WithContext(ctx).Where("refresh_token = ?", refreshToken).First(&accessToken)
	if result.Error != nil {
		return nil, result.Error
	}
	return &accessToken, nil
}
