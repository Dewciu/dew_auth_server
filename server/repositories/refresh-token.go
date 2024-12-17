package repositories

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
	"gorm.io/gorm"
)

var _ IRefreshTokenRepository = new(RefreshTokenRepository)

type IRefreshTokenRepository interface {
	GetWithID(ctx context.Context, id string) (*models.RefreshToken, error)
	Create(ctx context.Context, refreshToken *models.RefreshToken) error
	Update(ctx context.Context, refreshToken *models.RefreshToken) error
	GetByToken(ctx context.Context, token string) (*models.RefreshToken, error)
	GetByUserID(ctx context.Context, userID string) ([]models.RefreshToken, error)
	GetByClientID(ctx context.Context, clientID string) ([]models.RefreshToken, error)
}

type RefreshTokenRepository struct {
	database *gorm.DB
}

func NewRefreshTokenRepository(database *gorm.DB) IRefreshTokenRepository {
	return &RefreshTokenRepository{
		database: database,
	}
}

func (r *RefreshTokenRepository) GetWithID(ctx context.Context, id string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	result := r.database.Where("id = ?", id).First(&refreshToken)
	if result.Error != nil {
		return nil, result.Error
	}

	return &refreshToken, nil
}

func (r *RefreshTokenRepository) Create(ctx context.Context, refreshToken *models.RefreshToken) error {
	result := r.database.WithContext(ctx).Create(refreshToken)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *RefreshTokenRepository) Update(ctx context.Context, refreshToken *models.RefreshToken) error {
	result := r.database.WithContext(ctx).Save(refreshToken)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *RefreshTokenRepository) GetByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	result := r.database.WithContext(ctx).Where("token = ?", token).First(&refreshToken)
	if result.Error != nil {
		return nil, result.Error
	}
	return &refreshToken, nil
}

func (r *RefreshTokenRepository) GetByUserID(ctx context.Context, userID string) ([]models.RefreshToken, error) {
	var refreshTokens []models.RefreshToken
	result := r.database.WithContext(ctx).Where("user_id = ?", userID).Find(&refreshTokens)
	if result.Error != nil {
		return nil, result.Error
	}
	return refreshTokens, nil
}

func (r *RefreshTokenRepository) GetByClientID(ctx context.Context, clientID string) ([]models.RefreshToken, error) {
	var refreshTokens []models.RefreshToken
	result := r.database.WithContext(ctx).Where("client_id = ?", clientID).Find(&refreshTokens)
	if result.Error != nil {
		return nil, result.Error
	}
	return refreshTokens, nil
}
