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
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
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

	if client == nil {
		return "", errors.New("client cannot be nil")
	}

	code, err := generateRandomUrlBase64EncString(32)
	if err != nil {
		return "", err
	}

	authCode, err := cachemodels.NewAuthorizationCode(
		code,
		userID,
		client.ID.String(),
		redirectURI,
		client.Scopes,
		codeChallenge,
		codeChallengeMethod,
	)

	if err != nil {
		return "", err
	}

	if err = s.authorizationCodeRepository.Create(ctx, authCode); err != nil {
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
		return nil, serviceerrors.NewInvalidAuthorizationCodeError("empty")
	}

	codeDetails, err := s.authorizationCodeRepository.GetByCode(ctx, code)
	if err != nil || codeDetails == nil {
		logrus.WithError(err).WithField("code", code).Error("Failed to retrieve authorization code")
		return nil, serviceerrors.NewInvalidAuthorizationCodeError(code)
	}

	if codeDetails.RedirectURI != redirectUri {
		e := serviceerrors.NewInvalidRedirectURIError(redirectUri, codeDetails.RedirectURI)
		logrus.WithField("redirect_uri", redirectUri).WithField("code_redirect_uri", codeDetails.RedirectURI).Error(e)
		return nil, e
	}

	if codeDetails.ClientID != clientID {
		e := serviceerrors.NewTokenClientMismatchError(clientID, codeDetails.ClientID)
		logrus.WithField("client_id", clientID).WithField("code_client_id", codeDetails.ClientID).Error(e)
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
			return serviceerrors.NewInvalidPKCEVerifierError("code verifier does not match code challenge")
		}
	case string(constants.PlainMethod):
		if codeVerifier != codeChallenge {
			return serviceerrors.NewInvalidPKCEVerifierError("code verifier does not match code challenge")
		}
	default:
		return serviceerrors.NewUnsupportedPKCEMethodError(codeChallengeMethod)
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
