package repositories

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var _ IConsentRepository = new(ConsentRepository)

type IConsentRepository interface {
	GetForClientAndUser(ctx context.Context, clientID uuid.UUID, userID uuid.UUID) (*models.Consent, error)
	Create(ctx context.Context, consent *models.Consent) error
}

type ConsentRepository struct {
	database *gorm.DB
}

func NewConsentRepository(database *gorm.DB) IConsentRepository {
	return &ConsentRepository{
		database: database,
	}
}

func (r *ConsentRepository) GetForClientAndUser(ctx context.Context, clientID uuid.UUID, userID uuid.UUID) (*models.Consent, error) {
	var consent models.Consent
	result := r.database.Where(
		"client_id = ? AND user_id = ?",
		clientID,
		userID,
	).First(&consent)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &consent, result.Error
}

func (r *ConsentRepository) Create(ctx context.Context, consent *models.Consent) error {
	result := r.database.Create(consent)
	return result.Error
}
