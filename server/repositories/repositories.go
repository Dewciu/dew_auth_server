package repositories

type Repositories struct {
	AccessTokenRepository       IAccessTokenRepository
	AuthorizationCodeRepository IAuthorizationCodeRepository
	ClientRepository            IClientRepository
	RefreshTokenRepository      IRefreshTokenRepository
	UserRepository              IUserRepository
	ConsentRepository           IConsentRepository
}
