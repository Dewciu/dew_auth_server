package services

type Services struct {
	AccessTokenService       IAccessTokenService
	AuthorizationCodeService IAuthorizationCodeService
	RefreshTokenService      IRefreshTokenService
	ClientService            IClientService
}
