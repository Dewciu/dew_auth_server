package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/repositories"
)

var _ IAccessTokenService = new(AccessTokenService)

type IAccessTokenService interface {
	GenerateOpaqueToken(length int) (string, error)
}

type AccessTokenService struct {
	accessTokenRepository repositories.IAccessTokenRepository
}

func NewAccessTokenService(accessTokenRepository repositories.IAccessTokenRepository) AccessTokenService {
	return AccessTokenService{
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

func (s *AccessTokenService) CreateAccessToken(ctx context.Context, input *inputs.IAccessTokenInput) (string, error) {
	//TODO: Implement this
	return "", nil
}
