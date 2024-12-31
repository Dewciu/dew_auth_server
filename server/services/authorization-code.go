package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/google/uuid"
)

var _ IAuthorizationCodeService = new(AuthorizationCodeService)

type IAuthorizationCodeService interface {
	GenerateCode(ctx context.Context) (string, error)
	GenerateCodeWithPKCE(
		ctx context.Context,
		client *models.Client,
		userID string,
		redirectURI string,
		codeChallenge string,
		codeChallengeMethod string,
	) (string, error)
	ValidateCode(ctx context.Context, code string, redirectUri string, clientID string) (*models.AuthorizationCode, error)
	ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error
	SetCodeAsUsed(ctx context.Context, codeModel *models.AuthorizationCode) error
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
	code, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	// Save the code in the repository
	err = s.authorizationCodeRepository.Create(ctx, &models.AuthorizationCode{
		Code:      code,
		ExpiresAt: time.Now().Add(10 * time.Minute), // Set appropriate expiration time
	})
	if err != nil {
		return "", err
	}

	return code, nil
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

	code, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	//TODO: Expiration times from config
	err = s.authorizationCodeRepository.Create(ctx, &models.AuthorizationCode{
		UserID:              uuid.MustParse(userID),
		Client:              *client,
		RedirectURI:         redirectURI,
		Code:                code,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute), // Set appropriate expiration time
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
) (*models.AuthorizationCode, error) {
	if code == "" {
		return nil, errors.New("code is required")
	}

	codeDetails, err := s.authorizationCodeRepository.GetByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	currentTime := time.Now()

	if codeDetails.Used {
		return nil, errors.New("authorization code already used")
	}

	if codeDetails.ExpiresAt.Before(currentTime) {
		return nil, errors.New("authorization code expired")
	}

	if codeDetails.RedirectURI != redirectUri {
		return nil, errors.New("provided redirect URI does not match the URI associated with authorization code")
	}

	if codeDetails.ClientID.String() != clientID {
		return nil, errors.New("provided client ID does not match the ID associated with authorization code")
	}

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

func (s *AuthorizationCodeService) SetCodeAsUsed(ctx context.Context, codeModel *models.AuthorizationCode) error {
	codeModel.Used = true
	return s.authorizationCodeRepository.Update(ctx, codeModel)
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
