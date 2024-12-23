package services

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/google/uuid"
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

	return session.UserID.String(), nil
}
