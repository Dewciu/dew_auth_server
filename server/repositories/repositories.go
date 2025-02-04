package repositories

type Repositories struct {
	ClientRepository       IClientRepository
	RefreshTokenRepository IRefreshTokenRepository
	UserRepository         IUserRepository
	ConsentRepository      IConsentRepository
}
