package handlers

import (
	"context"
	"errors"
	"strings"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/sirupsen/logrus"
)

var _ IAuthorizationHandler = new(AuthorizationHandler)

type IAuthorizationHandler interface {
	Handle(input inputs.AuthorizationInput) error
}

type AuthorizationHandler struct {
	clientService   services.IClientService
	authCodeService services.IAuthorizationCodeService
	userService     services.IUserService
}

func NewAuthorizationHandler(
	clientService services.IClientService,
	authCodeService services.IAuthorizationCodeService,
	userService services.IUserService,
) IAuthorizationHandler {
	return &AuthorizationHandler{
		clientService:   clientService,
		authCodeService: authCodeService,
		userService:     userService,
	}
}

// TODO: User auth
func (h *AuthorizationHandler) Handle(input inputs.AuthorizationInput) error {
	ctx := context.Background()

	client, err := h.clientService.CheckIfClientExistsByID(ctx, input.ClientID)

	if err != nil {
		e := errors.New("client verification failed")
		logrus.WithError(err).Error(e)
		return e
	}

	if !strings.Contains(client.ResponseTypes, string(constants.TokenResponseType)) {
		e := errors.New("response type not allowed")
		logrus.Error(e)
		return e
	}

	if !strings.Contains(client.RedirectURI, input.RedirectURI) {
		e := errors.New("redirect uri not allowed")
		logrus.Error(e)
		return e
	}

	// user, err := h.userService.CheckIfUserExistsByID(ctx, input.UserID)

	return nil
}
