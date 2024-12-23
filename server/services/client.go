package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/repositories"
)

var _ IClientService = new(ClientService)

type IClientService interface {
	VerifyClientSecret(ctx context.Context, clientID string, clientSecret string) (*models.Client, error)
	CheckIfClientExists(ctx context.Context, clientName string) (bool, error)
	RegisterClient(
		ctx context.Context,
		clientName string,
		redirectUri string,
		email string,
		scopes string,
		responseTypes string,
		grantTypes string,
	) (*models.Client, error)
}

type ClientService struct {
	clientRepository repositories.IClientRepository
}

func NewClientService(clientRepository repositories.IClientRepository) ClientService {
	return ClientService{
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
	if client.Secret != clientSecret {
		return nil, errors.New("invalid client secret")
	}

	return client, nil
}

func (s *ClientService) CheckIfClientExists(
	ctx context.Context,
	clientName string,
) (bool, error) {
	client, err := s.clientRepository.GetWithName(ctx, clientName)
	if err != nil {
		return false, err
	}
	if client == nil {
		return false, nil
	}

	return true, nil
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
	clientName string,
	redirectUri string,
	email string,
	scopes string,
	responseTypes string,
	grantTypes string,
) (*models.Client, error) {

	clientSecret, err := s.GenerateClientSecret(64)
	if err != nil {
		return nil, err
	}

	client := &models.Client{
		Name:          clientName,
		Secret:        clientSecret,
		ContactEmail:  email,
		RedirectURI:   redirectUri,
		Scopes:        scopes,
		ResponseTypes: responseTypes,
		GrantTypes:    grantTypes,
	}

	err = s.clientRepository.Create(ctx, client)

	if err != nil {
		return nil, err
	}

	fmt.Println(client.ID)

	return client, nil
}
