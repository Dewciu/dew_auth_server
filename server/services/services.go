package services

type Services struct {
	AccessTokenService            IAccessTokenService
	AuthorizationCodeService      IAuthorizationCodeService
	RefreshTokenService           IRefreshTokenService
	ClientService                 IClientService
	UserService                   IUserService
	AuthorizationCodeGrantService IAuthorizationCodeGrantService
	AuthorizationService          IAuthorizationService
	ConsentService                IConsentService
}
