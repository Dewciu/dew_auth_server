package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
)

var _ IAuthorizationCodeService = new(AuthorizationCodeService)

type IAuthorizationCodeService interface {
	GenerateCode(ctx context.Context) (string, error)
	ValidateCode(ctx context.Context, code string, redirectUri string, clientID string) (*models.AuthorizationCode, error)
	ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error
}

type AuthorizationCodeService struct {
	authorizationCodeRepository repositories.IAuthorizationCodeRepository
}

func NewAuthorizationCodeService(authorizationCodeRepository repositories.IAuthorizationCodeRepository) AuthorizationCodeService {
	return AuthorizationCodeService{
		authorizationCodeRepository: authorizationCodeRepository,
	}
}

func (s *AuthorizationCodeService) GenerateCode(ctx context.Context) (string, error) {
	// Implement code generation logic
	return "generated_authorization_code", nil
}

func (s *AuthorizationCodeService) ValidateCode(ctx context.Context, code string, redirectUri string, clientID string) (*models.AuthorizationCode, error) {
	if code == "" {
		return nil, errors.New("code is required")
	}

	codeDetails, err := s.authorizationCodeRepository.GetByCode(ctx, code)

	if err != nil {
		return nil, err
	}

	currentTime := time.Now()

	if codeDetails.ExpiresAt.Before(currentTime) {
		return nil, errors.New("authorization code expired")
	}

	if codeDetails.RedirectURI != redirectUri {
		return nil, errors.New("provided redirect URI does not match the URI associated with authorization code")
	}

	if codeDetails.ClientID.String() != clientID {
		return nil, errors.New("provided client ID does not match the ID associated with authorization code")
	}
	// Implement code validation logic
	return codeDetails, nil
}

func (s *AuthorizationCodeService) ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	if codeVerifier == "" {
		return errors.New("PKCE code verifier is required")
	}

	switch codeChallengeMethod {
	case string(constants.SHA256Method):
		hasher := sha256.New()
		hasher.Write([]byte(codeVerifier))
		hashed := hasher.Sum(nil)

		encoded := base64.RawURLEncoding.EncodeToString(hashed)
		if encoded != codeChallenge {
			return errors.New("PKCE verification failed: code verifier does not match code challenge")
		}

	case string(constants.PlainMethod):
		if codeVerifier != codeChallenge {
			return errors.New("PKCE verification failed: code verifier does not match code challenge")
		}
	default:
		return errors.New("pkce verification failed: unsupported code challenge method")
	}

	return nil
}
