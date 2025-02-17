package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/cacherepositories"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/sirupsen/logrus"
)

var _ IAccessTokenService = new(AccessTokenService)

type IAccessTokenService interface {
	GenerateOpaqueToken(length int) (string, error)
	CreateToken(
		ctx context.Context,
		client *models.Client,
		userID string,
		scope string,
		tokenLength int,
	) (*cachemodels.AccessToken, error)
	GetTokenForUserClient(ctx context.Context, clientID string, userID string) (*cachemodels.AccessToken, error)
	GetTokenDetails(ctx context.Context, token string) (*cachemodels.AccessToken, error)
	RevokeToken(ctx context.Context, token *cachemodels.AccessToken) error
}

type AccessTokenService struct {
	accessTokenRepository cacherepositories.IAccessTokenRepository
}

func NewAccessTokenService(accessTokenRepository cacherepositories.IAccessTokenRepository) IAccessTokenService {
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

func (s *AccessTokenService) CreateToken(
	ctx context.Context,
	client *models.Client,
	userID string,
	scopes string,
	tokenLength int,
) (*cachemodels.AccessToken, error) {

	token, err := s.GenerateOpaqueToken(tokenLength)

	if err != nil {
		e := errors.New("failed to generate access token")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	existingAccessToken, err := s.GetTokenForUserClient(ctx, client.ID.String(), userID)
	if err != nil {
		e := errors.New("failed to get existing access token")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	if existingAccessToken != nil {
		return existingAccessToken, nil
	}

	tokenRecord, err := cachemodels.NewBearerAccessToken(
		token,
		scopes,
		client.ID.String(),
		userID,
	)

	//TODO: In future it should be client's domain
	tokenRecord.SetAudience(client.RedirectURI)
	//TODO: Set issuer from config - not hardcoded
	tokenRecord.SetIssuer("https://dew-auth-server.com")
	//TODO: Set username subject when user is implemented.
	// tokenRecord.SetSubject(user)

	if err != nil {
		e := errors.New("failed to create access token")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	if err = s.accessTokenRepository.Create(ctx, tokenRecord); err != nil {
		e := errors.New("failed to create access token")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	return tokenRecord, nil
}

func (s *AccessTokenService) GetTokenForUserClient(ctx context.Context, clientID string, userID string) (*cachemodels.AccessToken, error) {
	tokens, err := s.accessTokenRepository.GetByUserAndClient(ctx, userID, clientID)
	if err != nil {
		e := errors.New("failed to get access tokens by user and client index")
		logrus.WithError(err).Error(e)
		return nil, err
	}

	if len(tokens) == 0 {
		logrus.Info("no valid access tokens found for user and client")
		return nil, nil
	}

	if len(tokens) > 1 {
		e := errors.New("multiple access tokens found for user and client")
		logrus.Error(e)
		return nil, e
	}

	return tokens[0], nil
}

func (s *AccessTokenService) GetTokenDetails(ctx context.Context, token string) (*cachemodels.AccessToken, error) {
	tokenRecord, err := s.accessTokenRepository.GetByToken(ctx, token)
	if err != nil {
		e := errors.New("failed to get access token by token")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	return tokenRecord, nil
}

func (s *AccessTokenService) RevokeToken(ctx context.Context, token *cachemodels.AccessToken) error {
	err := s.accessTokenRepository.Update(ctx, token)
	if err != nil {
		e := errors.New("failed to delete access token")
		logrus.WithError(err).Error(e)
		return e
	}

	return nil
}
