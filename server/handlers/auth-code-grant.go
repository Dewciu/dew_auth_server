package handlers

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/sirupsen/logrus"
)

type AuthorizationCodeGrantHandler struct {
	accessTokenService services.IAccessTokenService
	clientService      services.IClientService
	authCodeService    services.IAuthorizationCodeService
}

func NewAuthorizationCodeGrantHandler(
	accessTokenService services.IAccessTokenService,
	clientService services.IClientService,
	authCodeService services.IAuthorizationCodeService,
) AuthorizationCodeGrantHandler {
	return AuthorizationCodeGrantHandler{
		accessTokenService: accessTokenService,
		clientService:      clientService,
		authCodeService:    authCodeService,
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

	//TODO: User validation
	user := &models.User{
		Username: "Test User",
		Email:    "testuser@example.com",
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

	return output, nil
}
