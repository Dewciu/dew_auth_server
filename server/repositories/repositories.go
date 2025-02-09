package repositories

type Repositories struct {
	ClientRepository  IClientRepository
	UserRepository    IUserRepository
	ConsentRepository IConsentRepository
}
