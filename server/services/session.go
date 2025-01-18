package services

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	serr "github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var _ ISessionService = new(SessionService)

type ISessionService interface {
	GetUserIDFromSession(ctx context.Context, sessionID string) (string, error)
	CreateSession(ctx context.Context, userID string, clientID string) (string, error)
}

type SessionService struct {
	sessionRepository repositories.ISessionRepository
}

func NewSessionService(sessionRepository repositories.ISessionRepository) ISessionService {
	return &SessionService{
		sessionRepository: sessionRepository,
	}
}

func (s *SessionService) GetUserIDFromSession(ctx context.Context, sessionID string) (string, error) {
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return "", err
	}

	session, err := s.sessionRepository.GetWithID(ctx, sessionUUID)
	if err != nil {
		return "", err
	}

	if session.UserID == uuid.Nil {
		err := serr.NewNoUserInSessionError(sessionID)
		logrus.Error(err)
		return "", err
	}

	return session.UserID.String(), nil
}

func (s *SessionService) CreateSession(
	ctx context.Context,
	userID string,
	clientID string,
) (string, error) {
	userUUID, err := uuid.Parse(userID)

	if err != nil {
		return "", err
	}
	clientUUID, err := uuid.Parse(clientID)

	if err != nil {
		return "", err
	}

	sessionID := uuid.New()

	session := &models.Session{
		UserID:   userUUID,
		ClientID: clientUUID,
	}

	session.ID = sessionID

	err = s.sessionRepository.Create(ctx, session)

	if err != nil {
		return "", err
	}

	return session.ID.String(), nil
}
