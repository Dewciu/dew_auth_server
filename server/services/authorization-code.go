package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/cacherepositories"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/sirupsen/logrus"
)

var _ IAuthorizationCodeService = new(AuthorizationCodeService)

type IAuthorizationCodeService interface {
	GenerateCodeWithPKCE(
		ctx context.Context,
		client *models.Client,
		userID string,
		redirectURI string,
		codeChallenge string,
		codeChallengeMethod string,
	) (string, error)

	ValidateCode(
		ctx context.Context,
		code string,
		redirectUri string,
		clientID string,
	) (*cachemodels.AuthorizationCode, error)

	ValidatePKCE(
		codeVerifier,
		codeChallenge,
		codeChallengeMethod string,
	) error
}

type AuthorizationCodeService struct {
	authorizationCodeRepository cacherepositories.IAuthorizationCodeRepository
}

func NewAuthorizationCodeService(authorizationCodeRepository cacherepositories.IAuthorizationCodeRepository) IAuthorizationCodeService {
	return &AuthorizationCodeService{
		authorizationCodeRepository: authorizationCodeRepository,
	}
}

func (s *AuthorizationCodeService) GenerateCodeWithPKCE(
	ctx context.Context,
	client *models.Client,
	userID string,
	redirectURI string,
	codeChallenge string,
	codeChallengeMethod string,
) (string, error) {
	if codeChallenge == "" || codeChallengeMethod == "" {
		return "", errors.New("code challenge and code challenge method are required")
	}

	code, err := generateRandomUrlBase64EncString(32)
	if err != nil {
		return "", err
	}

	err = s.authorizationCodeRepository.Create(ctx, &cachemodels.AuthorizationCode{
		UserID:              userID,
		RedirectURI:         redirectURI,
		Code:                code,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ClientID:            client.ID.String(),
		Scopes:              client.Scopes,
	})
	if err != nil {
		return "", err
	}

	return code, nil
}

func (s *AuthorizationCodeService) ValidateCode(
	ctx context.Context,
	code string,
	redirectUri string,
	clientID string,
) (*cachemodels.AuthorizationCode, error) {
	if code == "" {
		return nil, errors.New("code is required")
	}

	codeDetails, err := s.authorizationCodeRepository.GetByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	if codeDetails.RedirectURI != redirectUri {
		e := errors.New("provided redirect URI does not match the URI associated with authorization code")
		logrus.WithField("redirect_uri", redirectUri).WithField("code_redirect_uri", codeDetails.RedirectURI).Error(e)
		return nil, e
	}

	if codeDetails.ClientID != clientID {
		e := errors.New("provided client ID does not match the ID associated with authorization code")
		logrus.WithField("client_id", clientID).WithField("code_client_id", codeDetails.ClientID).Error(e)
		return nil, e
	}

	if codeDetails.CodeChallenge == "" {
		e := errors.New("missing PKCE code challenge in the authorization code data")
		logrus.Error(e)
		return nil, e
	}

	if codeDetails.CodeChallengeMethod == "" {
		e := errors.New("missing PKCE code challenge method in the authorization code data")
		logrus.Error(e)
		return nil, e
	}

	if codeDetails.Scopes == "" {
		e := errors.New("missing scopes in the authorization code data")
		logrus.Error(e)
		return nil, e
	}

	return codeDetails, nil
}

func (s *AuthorizationCodeService) ValidatePKCE(
	codeVerifier,
	codeChallenge,
	codeChallengeMethod string,
) error {
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

func generateRandomUrlBase64EncString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
