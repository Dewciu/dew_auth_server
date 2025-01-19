package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
)

var _ IClientService = new(ClientService)

type IClientService interface {
	VerifyClientSecret(ctx context.Context, clientID string, clientSecret string) (*models.Client, error)
	CheckIfClientExistsByName(ctx context.Context, clientName string) (*models.Client, error)
	CheckIfClientExistsByID(ctx context.Context, clientID string) (*models.Client, error)
	RegisterClient(
		ctx context.Context,
		input inputs.IClientRegisterInput,
	) (outputs.IClientRegisterOutput, error)
}

type ClientService struct {
	clientRepository repositories.IClientRepository
}

func NewClientService(clientRepository repositories.IClientRepository) IClientService {
	return &ClientService{
		clientRepository: clientRepository,
	}
}

func (s *ClientService) VerifyClientSecret(
	ctx context.Context,
	clientID string,
	clientSecret string,
) (*models.Client, error) {
	client, err := s.clientRepository.GetWithID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("client not found")
	}

	//TODO: client secret should be hashed in database
	decodedClientSecret, err := base64.StdEncoding.DecodeString(client.Secret)

	if err != nil {
		return nil, err
	}

	if string(decodedClientSecret) != clientSecret {
		return nil, errors.New("invalid client secret")
	}

	return client, nil
}

func (s *ClientService) CheckIfClientExistsByName(
	ctx context.Context,
	clientName string,
) (*models.Client, error) {
	client, err := s.clientRepository.GetWithName(ctx, clientName)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("client not found")
	}

	return client, nil
}

func (s *ClientService) CheckIfClientExistsByID(
	ctx context.Context,
	clientID string,
) (*models.Client, error) {
	client, err := s.clientRepository.GetWithID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("client not found")
	}

	return client, nil
}

func (s *ClientService) GenerateClientSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *ClientService) RegisterClient(
	ctx context.Context,
	input inputs.IClientRegisterInput,
) (outputs.IClientRegisterOutput, error) {
	var output outputs.ClientRegisterOutput

	clientSecret, err := s.GenerateClientSecret(64)
	if err != nil {
		return nil, err
	}

	b64clientSecret := base64.StdEncoding.EncodeToString([]byte(clientSecret))

	client := &models.Client{
		Name:          input.GetClientName(),
		Secret:        b64clientSecret,
		ContactEmail:  input.GetClientEmail(),
		RedirectURI:   input.GetRedirectURI(),
		Scopes:        input.GetScopes(),
		ResponseTypes: input.GetResponseTypes(),
		GrantTypes:    input.GetGrantTypes(),
	}

	err = s.clientRepository.Create(ctx, client)

	if err != nil {
		return nil, err
	}

	output.ClientID = client.ID.String()
	output.ClientSecret = clientSecret

	return &output, nil
}
