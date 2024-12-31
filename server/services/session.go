package services

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/repositories"
	serr "github.com/dewciu/dew_auth_server/server/services/service_errors"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var _ ISessionService = new(SessionService)

type ISessionService interface {
	GetUserIDFromSession(ctx context.Context, sessionID string) (string, error)
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
