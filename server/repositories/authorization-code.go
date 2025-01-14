package repositories

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/models"
	"gorm.io/gorm"
)

var _ IAuthorizationCodeRepository = new(AuthorizationCodeRepository)

type IAuthorizationCodeRepository interface {
	GetWithID(ctx context.Context, id string) (*models.AuthorizationCode, error)
	Create(ctx context.Context, authorizationCode *models.AuthorizationCode) error
	Update(ctx context.Context, authorizationCode *models.AuthorizationCode) error
	GetByCode(ctx context.Context, code string) (*models.AuthorizationCode, error)
	GetByUserID(ctx context.Context, userID string) ([]models.AuthorizationCode, error)
	GetByClientID(ctx context.Context, clientID string) ([]models.AuthorizationCode, error)
}

type AuthorizationCodeRepository struct {
	database *gorm.DB
}

func NewAuthorizationCodeRepository(database *gorm.DB) IAuthorizationCodeRepository {
	return &AuthorizationCodeRepository{
		database: database,
	}
}

func (r *AuthorizationCodeRepository) GetWithID(ctx context.Context, id string) (*models.AuthorizationCode, error) {
	var authorizationCode models.AuthorizationCode
	result := r.database.Where("id = ?", id).First(&authorizationCode)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &authorizationCode, result.Error
}

func (r *AuthorizationCodeRepository) Create(ctx context.Context, authorizationCode *models.AuthorizationCode) error {
	result := r.database.WithContext(ctx).Create(authorizationCode)
	return result.Error
}

func (r *AuthorizationCodeRepository) Update(ctx context.Context, authorizationCode *models.AuthorizationCode) error {
	result := r.database.WithContext(ctx).Save(authorizationCode)
	return result.Error
}

func (r *AuthorizationCodeRepository) GetByCode(ctx context.Context, code string) (*models.AuthorizationCode, error) {
	var authorizationCode models.AuthorizationCode
	result := r.database.WithContext(ctx).Where("code = ?", code).First(&authorizationCode)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &authorizationCode, result.Error
}

func (r *AuthorizationCodeRepository) GetByUserID(ctx context.Context, userID string) ([]models.AuthorizationCode, error) {
	var authorizationCodes []models.AuthorizationCode
	result := r.database.WithContext(ctx).Where("user_id = ?", userID).Find(&authorizationCodes)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return authorizationCodes, result.Error
}

func (r *AuthorizationCodeRepository) GetByClientID(ctx context.Context, clientID string) ([]models.AuthorizationCode, error) {
	var authorizationCodes []models.AuthorizationCode
	result := r.database.WithContext(ctx).Where("client_id = ?", clientID).Find(&authorizationCodes)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return authorizationCodes, result.Error
}
