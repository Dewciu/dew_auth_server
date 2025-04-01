package cacherepositories

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var _ IRefreshTokenRepository = new(RefreshTokenRepository)

type IRefreshTokenRepository interface {
	Create(ctx context.Context, tokenData *cachemodels.RefreshToken) error
	GetByToken(ctx context.Context, token string) (*cachemodels.RefreshToken, error)
	GetByUserAndClient(ctx context.Context, userID string, clientID string) ([]*cachemodels.RefreshToken, error)
	Update(ctx context.Context, tokenData *cachemodels.RefreshToken) error
}

type RefreshTokenRepository struct {
	keyPrefix          string
	usrClientIdxPrefix string
	ttl                time.Duration
	rdClient           *redis.Client
}

func NewRefreshTokenRepository(rdClient *redis.Client, ttl int) IRefreshTokenRepository {

	timeToLive := time.Duration(ttl) * time.Second

	return &RefreshTokenRepository{
		keyPrefix:          "refresh_token:",
		usrClientIdxPrefix: "rt_user_client_index:",
		ttl:                timeToLive,
		rdClient:           rdClient,
	}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, tokenData *cachemodels.RefreshToken) error {
	key := r.keyPrefix + tokenData.Token

	if tokenData.ExpiresIn == 0 {
		tokenData.SetExpiration(r.ttl)
	}

	expTime := time.Until(time.Unix(int64(tokenData.ExpiresIn), 0))

	if tokenData.IssuedAt == 0 {
		tokenData.SetIssuedTimeForNow()
	}

	if err := r.rdClient.HMSet(ctx, key, map[string]interface{}{
		"clientID": tokenData.ClientID,
		"userID":   tokenData.UserID,
		"scopes":   tokenData.Scopes,
		"exp":      tokenData.ExpiresIn,
		"iat":      tokenData.IssuedAt,
		"revoked":  tokenData.Revoked,
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

func (r *RefreshTokenRepository) GetByToken(ctx context.Context, token string) (*cachemodels.RefreshToken, error) {

	data, err := r.getDataByToken(ctx, token)

	if err != nil {
		return nil, err
	}

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

	revoked, err := strconv.ParseBool(data["revoked"])
	if err != nil {
		e := errors.New("failed to parse revoked status")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	RefreshToken := &cachemodels.RefreshToken{
		Token:     token,
		Scopes:    data["scopes"],
		ClientID:  data["clientID"],
		UserID:    data["userID"],
		ExpiresIn: exp,
		IssuedAt:  iss,
		Revoked:   revoked,
	}

	return RefreshToken, nil
}

func (r *RefreshTokenRepository) GetByUserAndClient(ctx context.Context, userID string, clientID string) ([]*cachemodels.RefreshToken, error) {

	key := r.getFullUserClientIndexKey(userID, clientID)

	tokensFromIndex, err := r.rdClient.SMembers(ctx, key).Result()

	tokens := make([]*cachemodels.RefreshToken, 0)

	if err != nil {
		e := fmt.Errorf("failed to get access tokens by user (%s) and client (%s) index", userID, clientID)
		logrus.WithError(err).Error(e)
		return nil, e
	}

	if len(tokensFromIndex) == 0 {
		logrus.Debugf("no access tokens found for user: %s and client %s", userID, clientID)
		return tokens, nil
	}

	for _, token := range tokensFromIndex {
		RefreshToken, err := r.GetByToken(ctx, token)

		if err != nil {
			continue
		}

		tokens = append(tokens, RefreshToken)
	}

	return tokens, nil
}

func (r *RefreshTokenRepository) Update(ctx context.Context, token *cachemodels.RefreshToken) error {
	key := r.keyPrefix + token.Token

	err := r.rdClient.HMSet(ctx, key, map[string]interface{}{
		"clientID": token.ClientID,
		"userID":   token.UserID,
		"scopes":   token.Scopes,
		"exp":      token.ExpiresIn,
		"iat":      token.IssuedAt,
		"revoked":  token.Revoked,
	}).Err()

	if err != nil {
		e := errors.New("failed to update access token")
		logrus.WithError(err).Error(e)
		return e
	}

	return nil
}

func (r *RefreshTokenRepository) getDataByToken(ctx context.Context, token string) (map[string]string, error) {
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

func (r *RefreshTokenRepository) createUserClientIndex(ctx context.Context, userID string, clientID string, token string, expTime time.Duration) error {
	key := r.getFullUserClientIndexKey(userID, clientID)

	if err := r.rdClient.SAdd(ctx, key, token).Err(); err != nil {
		return err
	}

	return r.rdClient.Expire(ctx, key, expTime).Err()
}

func (r *RefreshTokenRepository) getFullUserClientIndexKey(userID string, clientID string) string {
	return r.usrClientIdxPrefix + "userID:" + userID + ":clientID:" + clientID
}
