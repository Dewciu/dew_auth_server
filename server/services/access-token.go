package services

import "github.com/dewciu/dew_auth_server/server/repositories"

var _ IAccessTokenService = new(AccessTokenService)

type IAccessTokenService interface {
	GenerateToken() string
}

type AccessTokenService struct {
	repository repositories.IAccessTokenRepository
}

func NewAccessTokenService(repository repositories.IAccessTokenRepository) AccessTokenService {
	return AccessTokenService{
		repository: repository,
	}
}

func (s *AccessTokenService) GenerateToken() string {
	return ""
}
