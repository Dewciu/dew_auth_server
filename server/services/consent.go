package services

import (
	"context"
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
		logrus.WithError(err).Error("Error while checking if consent exists")
		return false, err
	}

	if consent == nil {
		logrus.Debugf("Consent for user with ID %s and client with ID %s does not exist", userID, clientID)
		return false, nil
	}

	if consent.RevokedAt != (time.Time{}) && consent.RevokedAt.Before(time.Now()) {
		logrus.Debugf("Consent for user with ID %s and client with ID %s exists but is revoked", userID, clientID)
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

	if err != nil {
		logrus.WithError(err).Error("Error while checking if consent exists")
		return nil, err
	}

	if dbConsent != nil {
		logrus.Debugf("Consent for user with ID %s and client with ID %s already exists", userID, clientID)

		if dbConsent.RevokedAt != (time.Time{}) && dbConsent.RevokedAt.Before(time.Now()) {
			logrus.Debugf("Consent for user with ID %s and client with ID %s is revoked", userID, clientID)
			dbConsent.RevokedAt = time.Time{}
			dbConsent.GrantedAt = time.Now()
			err := s.consentRepository.Update(ctx, dbConsent)
			if err != nil {
				logrus.WithError(err).Error("Error while updating consent")
				return nil, err
			}
			return dbConsent, nil
		}
	}

	consent := &models.Consent{
		ClientID:  uuid.MustParse(clientID),
		UserID:    uuid.MustParse(userID),
		Scopes:    scopes,
		GrantedAt: time.Now(),
	}

	if err := s.consentRepository.Create(ctx, consent); err != nil {
		return nil, err
	}

	return consent, nil
}
