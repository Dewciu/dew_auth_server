package repositories

type Repositories struct {
	AccessTokenRepository  IAccessTokenRepository
	ClientRepository       IClientRepository
	RefreshTokenRepository IRefreshTokenRepository
	UserRepository         IUserRepository
	ConsentRepository      IConsentRepository
}
