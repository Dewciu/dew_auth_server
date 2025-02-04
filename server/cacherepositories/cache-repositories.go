package cacherepositories

type CacheRepositories struct {
	AuthorizationCodeRepository IAuthorizationCodeRepository
	AccessTokenRepository       IAccessTokenRepository
}
