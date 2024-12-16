package services

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
)

var _ IClientService = new(ClientService)

type IClientService interface {
	VerifyClient(ctx context.Context, clientID string, clientSecret string) (*models.Client, error)
}

type ClientService struct {
	clientRepository repositories.IClientRepository
}

func NewClientService(clientRepository repositories.IClientRepository) ClientService {
	return ClientService{
		clientRepository: clientRepository,
	}
}

func (s *ClientService) VerifyClient(
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
	if client.Secret != clientSecret {
		return nil, errors.New("invalid client secret")
	}

	return client, nil
}
