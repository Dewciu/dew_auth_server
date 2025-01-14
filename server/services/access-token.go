package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/google/uuid"
)

var _ IAccessTokenService = new(AccessTokenService)

type IAccessTokenService interface {
	GenerateOpaqueToken(length int) (string, error)
	CreateAccessToken(
		ctx context.Context,
		clientID uuid.UUID,
		userID uuid.UUID,
		scope string,
		tokenLength int,
		expirationTime time.Duration,
	) (*outputs.AccessTokenOutput, error)
}

type AccessTokenService struct {
	accessTokenRepository repositories.IAccessTokenRepository
}

func NewAccessTokenService(accessTokenRepository repositories.IAccessTokenRepository) IAccessTokenService {
	return &AccessTokenService{
		accessTokenRepository: accessTokenRepository,
	}
}

func (s *AccessTokenService) GenerateOpaqueToken(length int) (string, error) {
	if length < 1 {
		return "", errors.New("invalid token length")
	}

	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	token := base64.RawURLEncoding.EncodeToString(b)
	return token, nil
}

func (s *AccessTokenService) CreateAccessToken(
	ctx context.Context,
	clientID uuid.UUID,
	userID uuid.UUID,
	scope string,
	tokenLength int,
	expirationTime time.Duration,
) (*outputs.AccessTokenOutput, error) {

	token, err := s.GenerateOpaqueToken(tokenLength)

	if err != nil {
		return nil, err
	}

	tokenRecord := &models.AccessToken{
		ClientID:  clientID,
		Scope:     scope,
		UserID:    userID,
		ExpiresAt: time.Now().Add(expirationTime),
		Token:     token,
	}

	if err := s.accessTokenRepository.Create(ctx, tokenRecord); err != nil {
		return nil, err
	}

	output := &outputs.AccessTokenOutput{
		AccessToken: token,
		TokenType:   string(constants.TokenTypeBearer),
		ExpiresIn:   int(expirationTime.Seconds()),
		Scope:       scope,
	}

	return output, nil
}
