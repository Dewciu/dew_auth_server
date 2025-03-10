package services

import (
	"context"
	"errors"
	"strings"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/sirupsen/logrus"
)

var _ IAuthorizationService = new(AuthorizationService)

type IAuthorizationService interface {
	AuthorizeClient(ctx context.Context, input inputs.IAuthorizationInput) (outputs.IAuthorizeOutput, error)
}

type AuthorizationService struct {
	clientService   IClientService
	authCodeService IAuthorizationCodeService
	userService     IUserService
}

func NewAuthorizationService(
	clientService IClientService,
	authCodeService IAuthorizationCodeService,
	userService IUserService,
) IAuthorizationService {
	return &AuthorizationService{
		clientService:   clientService,
		authCodeService: authCodeService,
		userService:     userService,
	}
}

func (h *AuthorizationService) AuthorizeClient(ctx context.Context, input inputs.IAuthorizationInput) (outputs.IAuthorizeOutput, error) {

	client, err := h.clientService.CheckIfClientExistsByID(ctx, input.GetClientID())

	if err != nil {
		logrus.Error(err)
		return nil, err
	}

	if !strings.Contains(client.ResponseTypes, string(constants.TokenResponseType)) {
		e := serviceerrors.NewUnsupportedResponseTypeError(client.ID.String(), constants.TokenResponseType)
		logrus.WithFields(
			logrus.Fields{
				"client_id":     client.ID.String(),
				"response_type": constants.TokenResponseType,
			},
		).Error(e)

		return nil, e
	}

	if !strings.Contains(client.RedirectURI, input.GetRedirectURI()) {
		e := serviceerrors.NewInvalidRedirectURIForClientError(client.ID.String(), input.GetRedirectURI())
		logrus.WithFields(logrus.Fields{
			"client_id": client.ID.String(),
			"uri":       input.GetRedirectURI(),
		}).Error(e)
		return nil, e
	}

	userID := appcontext.MustGetUserID(ctx)
	code, err := h.authCodeService.GenerateCodeWithPKCE(
		ctx,
		client,
		userID,
		input.GetRedirectURI(),
		input.GetCodeChallenge(),
		input.GetCodeChallengeMethod(),
	)

	if err != nil {
		e := errors.New("failed to generate authorization code")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	return outputs.AuthorizeOutput{
		Code:  code,
		State: input.GetState(),
	}, nil
}
