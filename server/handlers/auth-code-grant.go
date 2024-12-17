package handlers

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/sirupsen/logrus"
)

var _ IAuthorizationCodeGrantHandler = new(AuthorizationCodeGrantHandler)

type IAuthorizationCodeGrantHandler interface {
	Handle(input inputs.AuthorizationCodeGrantInput) (*outputs.AuthorizationCodeGrantOutput, error)
}

type AuthorizationCodeGrantHandler struct {
	accessTokenService  services.IAccessTokenService
	clientService       services.IClientService
	authCodeService     services.IAuthorizationCodeService
	refreshTokenService services.IRefreshTokenService
}

func NewAuthorizationCodeGrantHandler(
	accessTokenService services.IAccessTokenService,
	clientService services.IClientService,
	authCodeService services.IAuthorizationCodeService,
	refreshTokenService services.IRefreshTokenService,
) IAuthorizationCodeGrantHandler {
	return &AuthorizationCodeGrantHandler{
		accessTokenService:  accessTokenService,
		clientService:       clientService,
		authCodeService:     authCodeService,
		refreshTokenService: refreshTokenService,
	}
}

func (h *AuthorizationCodeGrantHandler) Handle(input inputs.AuthorizationCodeGrantInput) (*outputs.AuthorizationCodeGrantOutput, error) {
	var output *outputs.AuthorizationCodeGrantOutput
	ctx := context.Background()

	client, err := h.clientService.VerifyClient(ctx, input.ClientID, input.ClientSecret)

	if err != nil {
		e := errors.New("client verification failed")
		logrus.WithError(err).Error(e)
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

	output = &outputs.AuthorizationCodeGrantOutput{
		AccessTokenOutput: *accessTokenDetails,
		RefreshToken:      refreshToken,
	}

	return output, nil
}
