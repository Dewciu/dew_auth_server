package services

import (
	"errors"
	"strings"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	sc "github.com/dewciu/dew_auth_server/server/services/servicecontexts"
	"github.com/sirupsen/logrus"
)

var _ IAuthorizationService = new(AuthorizationService)

type IAuthorizationService interface {
	Handle(ctx sc.AuthorizationContext, input inputs.IAuthorizationInput) (outputs.IAuthorizeOutput, error)
}

type AuthorizationService struct {
	clientService   IClientService
	authCodeService IAuthorizationCodeService
	userService     IUserService
	sessionService  ISessionService
}

func NewAuthorizationService(
	clientService IClientService,
	authCodeService IAuthorizationCodeService,
	userService IUserService,
	sessionService ISessionService,
) IAuthorizationService {
	return &AuthorizationService{
		clientService:   clientService,
		authCodeService: authCodeService,
		userService:     userService,
		sessionService:  sessionService,
	}
}

// TODO: Better errors
func (h *AuthorizationService) Handle(ctx sc.AuthorizationContext, input inputs.IAuthorizationInput) (outputs.IAuthorizeOutput, error) {

	client, err := h.clientService.CheckIfClientExistsByID(ctx, input.GetClientID())

	if err != nil {
		e := errors.New("client verification failed")
		logrus.WithError(err).Error(e)
		return nil, e
	}

	if !strings.Contains(client.ResponseTypes, string(constants.TokenResponseType)) {
		e := errors.New("response type not allowed")
		logrus.Error(e)
		return nil, e
	}

	if !strings.Contains(client.RedirectURI, input.GetRedirectURI()) {
		e := errors.New("redirect uri not allowed")
		logrus.Error(e)
		return nil, e
	}

	code, err := h.authCodeService.GenerateCodeWithPKCE(
		ctx,
		client,
		ctx.UserID,
		input.GetRedirectURI(),
		input.GetCodeChallenge(),
		input.GetCodeChallengeMethod(),
	)

	if err != nil {
		logrus.WithError(err).Error("failed to generate authorization code")
		return nil, err
	}

	return outputs.AuthorizeOutput{
		Code:  code,
		State: input.GetState(),
	}, nil
}
