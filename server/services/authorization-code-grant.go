package services

import (
	"context"
	"errors"
	"strings"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/sirupsen/logrus"
)

var _ IAuthorizationCodeGrantService = new(AuthorizationCodeGrantService)

type IAuthorizationCodeGrantService interface {
	Handle(ctx context.Context, input inputs.AuthorizationCodeGrantInput) (*outputs.AuthorizationCodeGrantOutput, error)
}

type AuthorizationCodeGrantService struct {
	accessTokenService  IAccessTokenService
	clientService       IClientService
	authCodeService     IAuthorizationCodeService
	refreshTokenService IRefreshTokenService
}

func NewAuthorizationCodeGrantService(
	accessTokenService IAccessTokenService,
	clientService IClientService,
	authCodeService IAuthorizationCodeService,
	refreshTokenService IRefreshTokenService,
) IAuthorizationCodeGrantService {
	return &AuthorizationCodeGrantService{
		accessTokenService:  accessTokenService,
		clientService:       clientService,
		authCodeService:     authCodeService,
		refreshTokenService: refreshTokenService,
	}
}

//TODO: Consider refactoring things using goroutines and channels.

func (h *AuthorizationCodeGrantService) Handle(ctx context.Context, input inputs.AuthorizationCodeGrantInput) (*outputs.AuthorizationCodeGrantOutput, error) {
	var output *outputs.AuthorizationCodeGrantOutput

	client, err := h.clientService.VerifyClientSecret(ctx, input.ClientID, input.ClientSecret)

	if err != nil {
		e := errors.New("client verification failed")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	if !strings.Contains(client.GrantTypes, input.GrantType) {
		e := errors.New("grant type not allowed")
		logrus.Error(e)
		return nil, e
	}

	if !strings.Contains(client.ResponseTypes, string(constants.TokenResponseType)) {
		e := errors.New("response type not allowed")
		logrus.Error(e)
		return nil, e
	}

	codeDetails, err := h.authCodeService.ValidateCode(ctx, input.Code, input.RedirectURI, client.ID.String())

	if err != nil {
		e := errors.New("auth code verification failed")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	if err := h.authCodeService.ValidatePKCE(input.CodeVerifier, codeDetails.CodeChallenge, codeDetails.CodeChallengeMethod); err != nil {
		return nil, err
	}

	//TODO: Times and lengths need to be configurable.

	accessTokenDetails, err := h.accessTokenService.CreateAccessToken(
		ctx,
		client.ID,
		codeDetails.UserID,
		codeDetails.Scope,
		32,
		3600,
	)

	if err != nil {
		e := errors.New("access token creation failed")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	refreshToken, err := h.refreshTokenService.CreateRefreshToken(
		ctx,
		client.ID,
		codeDetails.UserID,
		codeDetails.Scope,
		32,
		3600,
	)

	if err != nil {
		e := errors.New("refresh token creation failed")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	err = h.authCodeService.SetCodeAsUsed(ctx, codeDetails)

	if err != nil {
		e := errors.New("auth code update failed")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	output = &outputs.AuthorizationCodeGrantOutput{
		AccessTokenOutput: *accessTokenDetails,
		RefreshToken:      refreshToken,
	}

	return output, nil
}
