package services

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/cachemodels"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/sirupsen/logrus"
)

// TODO: Make token length configurable
var _ IGrantService = new(GrantService)

type IGrantService interface {
	ObtainByAuthCode(ctx context.Context, input inputs.AuthorizationCodeGrantInput) (*outputs.GrantOutput, error)
	ObtainByRefreshToken(ctx context.Context, input inputs.RefreshTokenGrantInput, newRefreshToken bool) (*outputs.GrantOutput, error)
	ObtainByClientCredentials(ctx context.Context, input inputs.ClientCredentialsGrantInput) (*outputs.GrantOutput, error)
}

type GrantService struct {
	accessTokenService  IAccessTokenService
	clientService       IClientService
	authCodeService     IAuthorizationCodeService
	refreshTokenService IRefreshTokenService
}

func NewGrantService(
	accessTokenService IAccessTokenService,
	clientService IClientService,
	authCodeService IAuthorizationCodeService,
	refreshTokenService IRefreshTokenService,
) IGrantService {
	return &GrantService{
		accessTokenService:  accessTokenService,
		clientService:       clientService,
		authCodeService:     authCodeService,
		refreshTokenService: refreshTokenService,
	}
}

func (h *GrantService) ObtainByAuthCode(ctx context.Context, input inputs.AuthorizationCodeGrantInput) (*outputs.GrantOutput, error) {
	var output *outputs.GrantOutput
	var accessToken *cachemodels.AccessToken
	client := appcontext.MustGetClient(ctx)

	if !strings.Contains(client.GrantTypes, input.GrantType) {
		e := serviceerrors.NewUnsupportedGrantTypeError(client.ID.String(), constants.GrantType(input.GrantType))
		logrus.Debug(e)
		return nil, e
	}

	if !strings.Contains(client.ResponseTypes, string(constants.TokenResponseType)) {
		e := serviceerrors.NewUnsupportedResponseTypeError(client.ID.String(), constants.TokenResponseType)
		logrus.Debug(e)
		return nil, e
	}

	codeDetails, err := h.authCodeService.ValidateCode(ctx, input.Code, input.RedirectURI, client.ID.String())
	if err != nil {
		logrus.WithError(err).Debug("Auth code verification failed")
		return nil, err
	}

	if err := h.authCodeService.ValidatePKCE(input.CodeVerifier, codeDetails.CodeChallenge, codeDetails.CodeChallengeMethod); err != nil {
		logrus.WithError(err).Debug("PKCE validation failed")
		return nil, err
	}

	accessToken, err = h.accessTokenService.CreateToken(
		ctx,
		client,
		codeDetails.UserID,
		codeDetails.Scopes,
		64,
	)
	if err != nil {
		logrus.WithError(err).Debug("Access token creation failed")
		return nil, err
	}

	accessTokenOutput := outputs.AccessTokenOutput{
		Active:      true,
		AccessToken: *accessToken,
	}

	refreshToken, err := h.refreshTokenService.CreateRefreshToken(
		ctx,
		client.ID.String(),
		codeDetails.UserID,
		codeDetails.Scopes,
		32,
	)
	if err != nil {
		logrus.WithError(err).Error("Refresh token creation failed")
		return nil, err
	}

	output = &outputs.GrantOutput{
		AccessTokenOutput: accessTokenOutput,
		RefreshToken:      refreshToken,
	}

	return output, nil
}

func (h *GrantService) ObtainByRefreshToken(ctx context.Context, input inputs.RefreshTokenGrantInput, newRefreshToken bool) (*outputs.GrantOutput, error) {
	var output *outputs.GrantOutput
	var accessToken *cachemodels.AccessToken
	client := appcontext.MustGetClient(ctx)

	if !strings.Contains(client.GrantTypes, input.GrantType) {
		e := serviceerrors.NewUnsupportedGrantTypeError(client.ID.String(), constants.GrantType(input.GrantType))
		logrus.Debug(e)
		return nil, e
	}

	if !strings.Contains(client.ResponseTypes, string(constants.TokenResponseType)) {
		e := errors.New("response type not allowed")
		logrus.Debug(e)
		return nil, e
	}

	refreshTokenDetails, err := h.refreshTokenService.GetTokenDetails(ctx, input.RefreshToken)

	if err != nil {
		logrus.Debug(err)
		return nil, err
	}

	if refreshTokenDetails.ClientID != client.ID.String() {
		e := serviceerrors.NewClientAuthorizationError(client.ID.String(), "refresh token client mismatch")
		logrus.Debug(e)
		return nil, e
	}

	for _, scope := range strings.Split(client.Scopes, " ") {
		if !slices.Contains(strings.Split(refreshTokenDetails.Scopes, " "), scope) {
			e := serviceerrors.NewInvalidScopeError(client.ID.String(), scope)
			logrus.Debug(e)
			return nil, e
		}
	}

	accessToken, err = h.accessTokenService.CreateToken(
		ctx,
		client,
		refreshTokenDetails.UserID,
		refreshTokenDetails.Scopes,
		64,
	)

	if err != nil {
		e := errors.New("access token creation failed")
		logrus.WithError(err).Debug(e)
		return nil, e
	}

	accessTokenOutput := outputs.AccessTokenOutput{
		Active:      true,
		AccessToken: *accessToken,
	}

	refreshToken := input.RefreshToken
	if newRefreshToken {
		refreshToken, err = h.refreshTokenService.CreateRefreshToken(
			ctx,
			client.ID.String(),
			refreshTokenDetails.UserID,
			refreshTokenDetails.Scopes,
			32,
		)

		if err != nil {
			e := errors.New("refresh token creation failed")
			logrus.WithError(err).Debug(e)
			return nil, e
		}

		if err := h.refreshTokenService.RevokeToken(ctx, refreshTokenDetails); err != nil {
			e := errors.New("failed to revoke refresh token")
			logrus.WithError(err).Debug(e)
			return nil, e
		}
	}

	output = &outputs.GrantOutput{
		AccessTokenOutput: accessTokenOutput,
		RefreshToken:      refreshToken,
	}

	return output, nil
}

func (h *GrantService) ObtainByClientCredentials(ctx context.Context, input inputs.ClientCredentialsGrantInput) (*outputs.GrantOutput, error) {
	var output *outputs.GrantOutput
	var accessToken *cachemodels.AccessToken
	client := appcontext.MustGetClient(ctx)

	if input.Scopes != "" {
		clientScopes := strings.Split(client.Scopes, " ")
		requestScopes := strings.Split(input.Scopes, " ")

		for _, scope := range requestScopes {
			if !slices.Contains(clientScopes, scope) {
				e := serviceerrors.NewInvalidScopeError(client.ID.String(), scope)
				logrus.Error(e)
				return nil, e
			}
		}
	}

	if !strings.Contains(client.GrantTypes, string(constants.ClientCredentials)) {
		e := serviceerrors.NewUnsupportedGrantTypeError(
			client.ID.String(),
			constants.ClientCredentials,
		)
		logrus.Error(e)
		return nil, e
	}

	accessToken, err := h.accessTokenService.CreateToken(
		ctx,
		client,
		client.ID.String(), // Use client ID as user ID since client is acting on its own behalf
		input.Scopes,
		64,
	)

	if err != nil {
		e := errors.New("access token creation failed")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	accessTokenOutput := outputs.AccessTokenOutput{
		Active:      true,
		AccessToken: *accessToken,
	}

	output = &outputs.GrantOutput{
		AccessTokenOutput: accessTokenOutput,
		// No refresh token for client credentials flow
	}

	return output, nil
}
