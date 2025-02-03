package cachemodels

import (
	"github.com/dewciu/dew_auth_server/server/cacheerrors"
	"github.com/dewciu/dew_auth_server/server/constants"
)

// AccessToken represents the structure of an access token used for authentication.
type AccessToken struct {
	Token     string              // Token is the actual access token string.
	Scopes    string              // Scope defines the permissions granted by the token.
	ClientID  string              // ClientID is the identifier of the client that requested the token.
	UserID    string              // UserID is the identifier of the user to whom the token was issued.
	TokenType constants.TokenType // TokenType specifies the type of the token (e.g., Bearer).
	ExpiresIn int                 // ExpiresIn is the duration in seconds for which the token is valid.
	IssuedAt  int                 // IssuedAt is the timestamp when the token was issued.
	NotBefore int                 // NotBefore is the timestamp before which the token is not valid.
	Audience  string              // Audience specifies the intended recipients of the token.
	Subject   string              // Subject identifies the principal that is the subject of the token.
	Issuer    string              // Issuer identifies the entity that issued the token.
}

func (a *AccessToken) Validate() error {

	if a.Token == "" {
		return &cacheerrors.MissingTokenError{}
	}
	if a.Scopes == "" {
		return &cacheerrors.MissingScopesError{}
	}
	if a.ClientID == "" {
		return &cacheerrors.MissingClientIDError{}
	}
	if a.TokenType == "" {
		return &cacheerrors.MissingTokenTypeError{}
	}
	if a.ExpiresIn == 0 {
		return &cacheerrors.MissingExpiresInError{}
	}
	return nil
}
