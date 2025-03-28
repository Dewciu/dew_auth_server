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

var _ IConsentService = new(ConsentService)

type IConsentService interface {
	RevokeConsentForClientAndUser(ctx context.Context, clientID string, userID string) error
	ConsentForClientAndUserExists(ctx context.Context, clientID string, userID string) (bool, error)
	GrantConsentForClientAndUser(ctx context.Context, clientID string, userID string, scopes string) (*models.Consent, error)
}

type ConsentService struct {
	consentRepository repositories.IConsentRepository
}

func NewConsentService(consentRepository repositories.IConsentRepository) IConsentService {
	return &ConsentService{
		consentRepository: consentRepository,
	}
}

func (s *ConsentService) RevokeConsentForClientAndUser(ctx context.Context, clientID string, userID string) error {
	return nil
}

func (s *ConsentService) ConsentForClientAndUserExists(ctx context.Context, clientID string, userID string) (bool, error) {
	consent, err := s.consentRepository.GetForClientAndUser(
		ctx,
		uuid.MustParse(clientID),
		uuid.MustParse(userID),
	)

	if err != nil {
		if errors.Is(err, repositories.NewRecordNotFoundError(models.Consent{})) {
			return false, nil
		}
		logrus.WithError(err).Error("Error while checking if consent exists")
		return false, err
	}

	if consent == nil {
		logrus.Debugf("Consent for user with ID %s and client with ID %s does not exist", userID, clientID)
		return false, nil
	}

	logrus.Debugf("Consent for user with ID %s and client with ID %s exists", userID, clientID)
	return true, nil
}

func (s *ConsentService) GrantConsentForClientAndUser(ctx context.Context, clientID string, userID string, scopes string) (*models.Consent, error) {

	dbConsent, err := s.consentRepository.GetForClientAndUser(
		ctx,
		uuid.MustParse(clientID),
		uuid.MustParse(userID),
	)

	if err != nil && !errors.Is(err, repositories.NewRecordNotFoundError(models.Consent{})) {
		e := errors.New("consent check error")
		logrus.WithError(err).Error("Error while checking if consent exists")
		return nil, e
	}

	if dbConsent != nil {
		logrus.Debugf("Consent for user with ID %s and client with ID %s already exists", userID, clientID)
		return dbConsent, nil
	}

	consent := &models.Consent{
		ClientID:  uuid.MustParse(clientID),
		UserID:    uuid.MustParse(userID),
		Scopes:    scopes,
		GrantedAt: time.Now(),
	}

	if err := s.consentRepository.Create(ctx, consent); err != nil {
		return nil, errors.New("consent creation error")
	}

	return consent, nil
}
