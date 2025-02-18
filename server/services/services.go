package services

type Services struct {
	AccessTokenService            IAccessTokenService
	AuthorizationCodeService      IAuthorizationCodeService
	RefreshTokenService           IRefreshTokenService
	ClientService                 IClientService
	UserService                   IUserService
	AuthorizationCodeGrantService IGrantService
	AuthorizationService          IAuthorizationService
	ConsentService                IConsentService
}
