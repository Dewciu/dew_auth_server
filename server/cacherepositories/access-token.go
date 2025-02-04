package cacherepositories

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var _ IAccessTokenRepository = new(AccessTokenRepository)

type IAccessTokenRepository interface {
	Create(ctx context.Context, tokenData *cachemodels.AccessToken) error
	GetByToken(ctx context.Context, token string) (*cachemodels.AccessToken, error)
}

type AccessTokenRepository struct {
	keyPrefix string
	ttl       time.Duration
	rdClient  *redis.Client
}

func NewAccessTokenRepository(rdClient *redis.Client, ttl time.Duration) IAccessTokenRepository {
	return &AccessTokenRepository{
		keyPrefix: "access_token:",
		ttl:       ttl,
		rdClient:  rdClient,
	}
}

func (r *AccessTokenRepository) Create(ctx context.Context, tokenData *cachemodels.AccessToken) error {
	key := r.keyPrefix + tokenData.Token

	if tokenData.ExpiresIn == 0 {
		tokenData.ExpiresIn = int(time.Now().Add(r.ttl).Unix())
	}

	if tokenData.IssuedAt == 0 {
		tokenData.IssuedAt = int(time.Now().Unix())
	}

	if err := r.rdClient.HMSet(ctx, key, map[string]interface{}{
		"tokenType": tokenData.TokenType,
		"clientID":  tokenData.ClientID,
		"userID":    tokenData.UserID,
		"scopes":    tokenData.Scopes,
		"exp":       tokenData.ExpiresIn,
		"iat":       tokenData.IssuedAt,
		"nbf":       tokenData.NotBefore,
		"aud":       tokenData.Audience,
		"sub":       tokenData.Subject,
		"iss":       tokenData.Issuer,
	}).Err(); err != nil {
		e := errors.New("failed to create access token")
		logrus.WithError(err).Error(e)
		return e
	}

	return r.rdClient.Expire(ctx, key, r.ttl).Err()
}

func (r *AccessTokenRepository) GetByToken(ctx context.Context, token string) (*cachemodels.AccessToken, error) {

	data, err := r.getData(ctx, token)

	if err != nil {
		return nil, err
	}

	tokenType := constants.TokenType(data["tokenType"])
	exp, err := strconv.Atoi(data["exp"])
	if err != nil {
		e := errors.New("failed to parse expiration time")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	iss, err := strconv.Atoi(data["iss"])
	if err != nil {
		e := errors.New("failed to parse issued time")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	nbf, err := strconv.Atoi(data["nbf"])
	if err != nil {
		e := errors.New("failed to parse not before time")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	accessToken := &cachemodels.AccessToken{
		Token:     token,
		Scopes:    data["scopes"],
		ClientID:  data["clientID"],
		UserID:    data["userID"],
		TokenType: tokenType,
		ExpiresIn: exp,
		IssuedAt:  iss,
		NotBefore: nbf,
		Audience:  data["aud"],
		Subject:   data["sub"],
		Issuer:    data["iss"],
	}

	return accessToken, nil
}

func (r *AccessTokenRepository) getData(ctx context.Context, token string) (map[string]string, error) {
	key := r.keyPrefix + token

	data, err := r.rdClient.HGetAll(ctx, key).Result()

	if err == redis.Nil || len(data) == 0 {
		e := errors.New("access token is invalid or expired")
		logrus.Debug(e.Error() + ": " + token)
		return nil, e
	}

	if err != nil {
		e := errors.New("failed to get access token")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	return data, nil
}
