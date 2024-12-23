package repositories

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var _ ISessionRepository = new(SessionRepository)

type ISessionRepository interface {
	GetWithID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	Create(ctx context.Context, session *models.Session) error
	DeleteWithID(ctx context.Context, id uuid.UUID) error
	Update(ctx context.Context, session *models.Session) error
}

type SessionRepository struct {
	database *gorm.DB
}

func NewSessionRepository(database *gorm.DB) ISessionRepository {
	return &SessionRepository{
		database: database,
	}
}

func (r *SessionRepository) GetWithID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	var session models.Session
	result := r.database.Where("id = ?", id).First(&session)
	if result.Error != nil {
		return nil, result.Error
	}

	return &session, nil
}

func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	result := r.database.WithContext(ctx).Create(session)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *SessionRepository) DeleteWithID(ctx context.Context, id uuid.UUID) error {
	result := r.database.WithContext(ctx).Where("id = ?", id).Delete(&models.Session{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *SessionRepository) Update(ctx context.Context, session *models.Session) error {
	result := r.database.WithContext(ctx).Save(session)
	if result.Error != nil {
		return result.Error
	}
	return nil
}
