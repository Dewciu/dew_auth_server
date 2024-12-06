package constants

type GrantType string

const (
	AuthorizationCode GrantType = "authorization_code"
	ClientCredentials GrantType = "client_credentials"
	RefreshToken      GrantType = "refresh_token"
	Password          GrantType = "password"
)
