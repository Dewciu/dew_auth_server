package handlers

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/services"
)

var _ IRegisterHandler = new(RegisterHandler)

type IRegisterHandler interface {
	HandleClient(input inputs.IClientRegisterInput) (outputs.IClientRegisterOutput, error)
}

type RegisterHandler struct {
	clientService services.IClientService
}

func NewRegisterHandler(
	clientService services.IClientService,
) *RegisterHandler {
	return &RegisterHandler{
		clientService: clientService,
	}
}

// TODO: Do a better error handling, create error structs etc.
func (h *RegisterHandler) HandleClient(
	input inputs.IClientRegisterInput,
) (outputs.IClientRegisterOutput, error) {
	ctx := context.Background()
	var output outputs.ClientRegisterOutput

	//TODO: Better error handling for verification if client exists

	// exists, err := h.clientService.CheckIfClientExists(ctx, input.GetClientName())
	// if err != nil {
	// 	return nil, err
	// }

	// if exists {
	// 	return nil, errors.New("client already exists")
	// }

	registeredClient, err := h.clientService.RegisterClient(
		ctx,
		input.GetClientName(),
		input.GetRedirectURI(),
		input.GetClientEmail(),
		input.GetScopes(),
		input.GetResponseTypes(),
		input.GetGrantTypes(),
	)

	if err != nil {
		return nil, err
	}

	output.ClientID = registeredClient.ID.String()
	output.ClientSecret = registeredClient.Secret

	return &output, nil
}
