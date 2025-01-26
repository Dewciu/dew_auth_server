package services

import (
	"context"
	"errors"
	"time"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var _ ISessionService = new(SessionService)

type ISessionService interface {
	RetrieveValidSession(ctx context.Context, sessionID string) (*models.Session, error)
	CreateSession(ctx context.Context, userID string, clientID string, duration int) (*models.Session, error)
	RevokeSessionByID(ctx context.Context, sessionID string) error
	CheckIfSessionIsValid(ctx context.Context, sessionID string) (bool, error)
}

type SessionService struct {
	sessionRepository repositories.ISessionRepository
}

func NewSessionService(sessionRepository repositories.ISessionRepository) ISessionService {
	return &SessionService{
		sessionRepository: sessionRepository,
	}
}

func (s *SessionService) RetrieveValidSession(ctx context.Context, sessionID string) (*models.Session, error) {
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, err
	}

	session, err := s.sessionRepository.GetWithID(ctx, sessionUUID)

	if err != nil {
		return nil, err
	}

	if session == nil {
		er := errors.New("session not found")
		logrus.Error(er)
		return nil, er
	}

	if session.ExpiresAt.Before(time.Now()) {
		er := errors.New("session expired")
		logrus.Error(er)
		return nil, er
	}

	return session, nil
}

// Duration in milliseconds
func (s *SessionService) CreateSession(
	ctx context.Context,
	userID string,
	clientID string,
	duration int,
) (*models.Session, error) {
	userUUID, err := uuid.Parse(userID)

	if err != nil {
		return nil, err
	}
	clientUUID, err := uuid.Parse(clientID)

	if err != nil {
		return nil, err
	}

	sessionID := uuid.New()

	expiresAt := time.Now().Add(time.Duration(duration) * time.Second)

	session := &models.Session{
		UserID:    userUUID,
		ClientID:  clientUUID,
		ExpiresAt: expiresAt,
	}

	session.ID = sessionID

	err = s.sessionRepository.Create(ctx, session)

	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *SessionService) RevokeSessionByID(ctx context.Context, sessionID string) error {
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return err
	}

	session, err := s.sessionRepository.GetWithID(ctx, sessionUUID)

	if err != nil {
		return err
	}

	session.ExpiresAt = time.Now()

	err = s.sessionRepository.Update(ctx, session)

	if err != nil {
		return err
	}

	return nil
}

func (s *SessionService) CheckIfSessionIsValid(ctx context.Context, sessionID string) (bool, error) {
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return false, err
	}

	session, err := s.sessionRepository.GetWithID(ctx, sessionUUID)
	if err != nil {
		return false, err
	}

	if session.ExpiresAt.Before(time.Now()) {
		return false, nil
	}

	return true, nil
}
