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
	GetByUserAndClient(ctx context.Context, userID string, clientID string) ([]*cachemodels.AccessToken, error)
}

type AccessTokenRepository struct {
	keyPrefix          string
	usrClientIdxPrefix string
	ttl                time.Duration
	rdClient           *redis.Client
}

func NewAccessTokenRepository(rdClient *redis.Client, ttl int) IAccessTokenRepository {

	timeToLive := time.Duration(ttl) * time.Second

	return &AccessTokenRepository{
		keyPrefix:          "access_token:",
		usrClientIdxPrefix: "user_client_index:",
		ttl:                timeToLive,
		rdClient:           rdClient,
	}
}

func (r *AccessTokenRepository) Create(ctx context.Context, tokenData *cachemodels.AccessToken) error {
	key := r.keyPrefix + tokenData.Token

	if tokenData.ExpiresIn == 0 {
		tokenData.SetExpiration(r.ttl)
	}

	expTime := time.Until(time.Unix(int64(tokenData.ExpiresIn), 0))

	if tokenData.IssuedAt == 0 {
		tokenData.SetIssuedTimeForNow()
	}

	if tokenData.NotBefore == 0 {
		tokenData.SetNotBeforeForNow()
	}

	if err := r.rdClient.HMSet(ctx, key, map[string]interface{}{
		"tokenType": string(tokenData.TokenType),
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

	if err := r.createUserClientIndex(ctx, tokenData.UserID, tokenData.ClientID, tokenData.Token, expTime); err != nil {
		e := errors.New("failed to create index for user and client")
		logrus.WithError(err).Error(e)
		return err
	}

	return r.rdClient.Expire(ctx, key, expTime).Err()
}

func (r *AccessTokenRepository) GetByToken(ctx context.Context, token string) (*cachemodels.AccessToken, error) {

	data, err := r.getDataByToken(ctx, token)

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

	iss, err := strconv.Atoi(data["iat"])
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

func (r *AccessTokenRepository) GetByUserAndClient(ctx context.Context, userID string, clientID string) ([]*cachemodels.AccessToken, error) {

	key := r.getFullUserClientIndexKey(userID, clientID)

	tokensFromIndex, err := r.rdClient.SMembers(ctx, key).Result()

	tokens := make([]*cachemodels.AccessToken, 0)

	if err != nil {
		e := errors.New("failed to get access tokens by user and client index")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	if len(tokensFromIndex) == 0 {
		logrus.Info("no access tokens found for user and client")
		return tokens, nil
	}

	for _, token := range tokensFromIndex {
		accessToken, err := r.GetByToken(ctx, token)

		if err != nil {
			continue
		}

		tokens = append(tokens, accessToken)
	}

	return tokens, nil
}

func (r *AccessTokenRepository) getDataByToken(ctx context.Context, token string) (map[string]string, error) {
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

func (r *AccessTokenRepository) createUserClientIndex(ctx context.Context, userID string, clientID string, token string, expTime time.Duration) error {
	key := r.getFullUserClientIndexKey(userID, clientID)

	if err := r.rdClient.SAdd(ctx, key, token).Err(); err != nil {
		return err
	}

	return r.rdClient.Expire(ctx, key, expTime).Err()
}

func (r *AccessTokenRepository) getFullUserClientIndexKey(userID string, clientID string) string {
	return r.usrClientIdxPrefix + "userID:" + userID + ":clientID:" + clientID
}
