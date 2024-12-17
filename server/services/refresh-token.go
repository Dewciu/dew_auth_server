package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/google/uuid"
)

var _ IRefreshTokenService = new(RefreshTokenService)

type IRefreshTokenService interface {
	GenerateOpaqueToken(length int) (string, error)
	CreateRefreshToken(
		ctx context.Context,
		clientID uuid.UUID,
		userID uuid.UUID,
		scope string,
		tokenLength int,
		expirationTime time.Duration,
	) (string, error)
}

type RefreshTokenService struct {
	refreshTokenRepository repositories.IRefreshTokenRepository
}

func NewRefreshTokenService(refreshTokenRepository repositories.IRefreshTokenRepository) RefreshTokenService {
	return RefreshTokenService{
		refreshTokenRepository: refreshTokenRepository,
	}
}

func (s *RefreshTokenService) GenerateOpaqueToken(length int) (string, error) {
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

func (s *RefreshTokenService) CreateRefreshToken(
	ctx context.Context,
	clientID uuid.UUID,
	userID uuid.UUID,
	scope string,
	tokenLength int,
	expirationTime time.Duration,
) (string, error) {

	token, err := s.GenerateOpaqueToken(tokenLength)

	if err != nil {
		return "", err
	}

	tokenRecord := &models.RefreshToken{
		ClientID:  clientID,
		Scope:     scope,
		UserID:    userID,
		ExpiresAt: time.Now().Add(expirationTime),
		Token:     token,
	}

	if err := s.refreshTokenRepository.Create(ctx, tokenRecord); err != nil {
		return "", err
	}

	return token, nil
}
