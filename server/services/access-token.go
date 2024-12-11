package services

import (
	"errors"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/repositories"
)

var _ IAccessTokenService = new(AccessTokenService)

type IAccessTokenService interface {
	GenerateToken(input inputs.IAccessTokenInput) (string, error)
}

type AccessTokenService struct {
	repository repositories.IAccessTokenRepository
}

func NewAccessTokenService(repository repositories.IAccessTokenRepository) AccessTokenService {
	return AccessTokenService{
		repository: repository,
	}
}

func (s *AccessTokenService) GenerateToken(input inputs.IAccessTokenInput) (string, error) {
	switch i := input.(type) {
	case inputs.AuthorizationCodeGrantInput:
		return s.handleAuthorizationCodeGrant(i)
	case inputs.RefreshTokenGrantInput:
		return s.handleRefreshTokenGrant(i)
	default:
		return "", errors.New("unsupported grant type or invalid input")
	}
}

func (s *AccessTokenService) handleAuthorizationCodeGrant(input inputs.AuthorizationCodeGrantInput) (string, error) {
	if input.Code == "" || input.RedirectURI == "" || input.CodeVerifier == "" {
		return "", errors.New("missing required fields for authorization code grant")
	}
	// Implement token generation logic
	return "generated_token_for_auth_code", nil
}

func (s *AccessTokenService) handleRefreshTokenGrant(input inputs.RefreshTokenGrantInput) (string, error) {
	if input.RefreshToken == "" || input.ClientSecret == "" {
		return "", errors.New("missing required fields for refresh token grant")
	}
	// Implement token generation logic
	return "generated_token_for_refresh_token", nil
}
