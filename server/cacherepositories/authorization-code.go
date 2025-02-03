package cacherepositories

import (
	"context"
	"errors"
	"time"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var _ IAuthorizationCodeRepository = new(AuthorizationCodeRepository)

type IAuthorizationCodeRepository interface {
	Create(ctx context.Context, codeData *cachemodels.AuthorizationCode) error
	GetByCode(ctx context.Context, code string) (*cachemodels.AuthorizationCode, error)
}

type AuthorizationCodeRepository struct {
	keyPrefix string
	ttl       time.Duration
	rdClient  *redis.Client
}

func NewAuthorizationCodeRepository(rdClient *redis.Client, ttl time.Duration) IAuthorizationCodeRepository {
	return &AuthorizationCodeRepository{
		keyPrefix: "authorization_code:",
		ttl:       ttl,
		rdClient:  rdClient,
	}
}

func (r *AuthorizationCodeRepository) Create(ctx context.Context, codeData *cachemodels.AuthorizationCode) error {
	key := r.keyPrefix + codeData.Code

	if err := r.rdClient.HMSet(ctx, key, map[string]interface{}{
		"userID":              codeData.UserID,
		"clientID":            codeData.ClientID,
		"redirectURI":         codeData.RedirectURI,
		"scopes":              codeData.Scopes,
		"codeChallenge":       codeData.CodeChallenge,
		"codeChallengeMethod": codeData.CodeChallengeMethod,
	}).Err(); err != nil {
		e := errors.New("failed to create authorization code")
		logrus.WithError(err).Error(e)
		return e
	}

	return r.rdClient.Expire(ctx, key, r.ttl).Err()
}

func (r *AuthorizationCodeRepository) GetByCode(ctx context.Context, code string) (*cachemodels.AuthorizationCode, error) {

	data, err := r.getData(ctx, code)

	if err != nil {
		return nil, err
	}

	authCode, err := cachemodels.NewAuthorizationCode(
		code,
		data["userID"],
		data["clientID"],
		data["redirectURI"],
		data["scopes"],
		data["codeChallenge"],
		data["codeChallengeMethod"],
	)

	if err != nil {
		return nil, err
	}

	return authCode, nil
}

func (r *AuthorizationCodeRepository) getData(ctx context.Context, code string) (map[string]string, error) {
	key := r.keyPrefix + code

	data, err := r.rdClient.HGetAll(ctx, key).Result()

	if err == redis.Nil || len(data) == 0 {
		e := errors.New("authorization is invalid or expired")
		logrus.Debug(e.Error() + ": " + code)
		return nil, e
	}

	if err != nil {
		e := errors.New("failed to get authorization code")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	return data, nil
}
