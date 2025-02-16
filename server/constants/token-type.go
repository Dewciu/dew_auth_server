package constants

type TokenType string

const (
	TokenTypeBearer  TokenType = "Bearer"
	TokenTypeRefresh TokenType = "refresh_token"
	TokenTypeAccess  TokenType = "access_token"
)
