package services

type Services struct {
	AccessTokenService            IAccessTokenService
	AuthorizationCodeService      IAuthorizationCodeService
	RefreshTokenService           IRefreshTokenService
	ClientService                 IClientService
	UserService                   IUserService
	SessionService                ISessionService
	AuthorizationCodeGrantService IAuthorizationCodeGrantService
	AuthorizationService          IAuthorizationService
}
