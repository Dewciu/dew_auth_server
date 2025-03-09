package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/cacherepositories"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/sirupsen/logrus"
)

var _ IRefreshTokenService = new(RefreshTokenService)

type IRefreshTokenService interface {
	GenerateOpaqueToken(length int) (string, error)
	CreateRefreshToken(
		ctx context.Context,
		clientID string,
		userID string,
		scope string,
		tokenLength int,
	) (string, error)
	GetTokenDetails(ctx context.Context, token string) (*cachemodels.RefreshToken, error)
	RevokeToken(ctx context.Context, token *cachemodels.RefreshToken) error
}

type RefreshTokenService struct {
	refreshTokenRepository cacherepositories.IRefreshTokenRepository
}

func NewRefreshTokenService(refreshTokenRepository cacherepositories.IRefreshTokenRepository) IRefreshTokenService {
	return &RefreshTokenService{
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
	clientID string,
	userID string,
	scope string,
	tokenLength int,
) (string, error) {

	token, err := s.GenerateOpaqueToken(tokenLength)

	if err != nil {
		return "", err
	}

	existingRefreshToken, err := s.GetExistingRefreshToken(ctx, clientID, userID)
	if err != nil {
		e := errors.New("failed to get existing refresh token")
		logrus.WithError(err).Error(e)
		return "", e
	}

	if existingRefreshToken != nil {
		return existingRefreshToken.Token, nil
	}

	tokenRecord, err := cachemodels.NewRefreshToken(
		token,
		scope,
		clientID,
		userID,
	)

	if err != nil {
		return "", err
	}

	if err := s.refreshTokenRepository.Create(ctx, tokenRecord); err != nil {
		return "", err
	}

	return token, nil
}

func (s *RefreshTokenService) GetExistingRefreshToken(ctx context.Context, clientID string, userID string) (*cachemodels.RefreshToken, error) {
	tokens, err := s.refreshTokenRepository.GetByUserAndClient(ctx, userID, clientID)
	validTokens := make([]*cachemodels.RefreshToken, 0)

	for _, token := range tokens {
		if token.IsActive() {
			validTokens = append(validTokens, token)
		}
	}

	if err != nil {
		e := errors.New("failed to get refresh tokens by user and client index")
		logrus.WithError(err).Error(e)
		return nil, err
	}

	if len(validTokens) == 0 {
		logrus.Info("no valid refresh tokens found for user and client")
		return nil, nil
	}

	if len(validTokens) > 1 {
		e := errors.New("multiple active refresh tokens found for user and client")
		logrus.Error(e)
		return nil, e
	}

	return validTokens[0], nil
}

func (s *RefreshTokenService) GetTokenDetails(ctx context.Context, token string) (*cachemodels.RefreshToken, error) {
	tokenRecord, err := s.refreshTokenRepository.GetByToken(ctx, token)
	if err != nil {
		e := serviceerrors.NewTokenNotFoundError(token)
		logrus.WithError(err).Info(e)
		return nil, e
	}

	return tokenRecord, nil
}

func (s *RefreshTokenService) RevokeToken(ctx context.Context, token *cachemodels.RefreshToken) error {
	token.Revoke()
	if err := s.refreshTokenRepository.Create(ctx, token); err != nil {
		return err
	}

	return nil
}
