package services

import (
	"context"
	"errors"

	"github.com/dewciu/dew_auth_server/server/repositories"
)

var _ IClientService = new(ClientService)

type IClientService interface {
	VerifyClient(ctx context.Context, clientID string) (bool, error)
}

type ClientService struct {
	clientRepository repositories.IClientRepository
}

func NewClientService(clientRepository repositories.IClientRepository) ClientService {
	return ClientService{
		clientRepository: clientRepository,
	}
}

func (s *ClientService) VerifyClient(ctx context.Context, clientID string) (bool, error) {
	client, err := s.clientRepository.GetWithID(ctx, clientID)
	if err != nil {
		return false, err
	}
	if client == nil {
		return false, errors.New("client not found")
	}
	return true, nil
}
