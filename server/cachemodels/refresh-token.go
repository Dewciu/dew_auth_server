package cachemodels

import (
	"time"

	"github.com/dewciu/dew_auth_server/server/cacheerrors"
)

type RefreshToken struct {
	Token     string `json:"refresh_token"` // Token is the actual access token string.
	Scopes    string `json:"scopes"`        // Scope defines the permissions granted by the token.
	ClientID  string `json:"client_id"`     // ClientID is the identifier of the client that requested the token.
	UserID    string `json:"user_id"`       // UserID is the identifier of the user to whom the token was issued.
	ExpiresIn int    `json:"exp"`           // ExpiresIn is the duration in seconds for which the token is valid.
	IssuedAt  int    `json:"iat"`           // IssuedAt is the timestamp when the token was issued.
	Revoked   bool   `json:"revoked"`       // Revoked indicates whether the token has been revoked.
}

func NewRefreshToken(
	token string,
	scopes string,
	clientID string,
	userID string,
) (*RefreshToken, error) {

	refreshToken := &RefreshToken{
		Token:    token,
		Scopes:   scopes,
		ClientID: clientID,
		UserID:   userID,
	}

	if err := refreshToken.Validate(); err != nil {
		return nil, err
	}

	return refreshToken, nil
}

func (a *RefreshToken) Validate() error {

	if a.Token == "" {
		return &cacheerrors.MissingTokenError{}
	}
	if a.Scopes == "" {
		return &cacheerrors.MissingScopesError{}
	}
	if a.ClientID == "" {
		return &cacheerrors.MissingClientIDError{}
	}
	return nil
}

func (a *RefreshToken) Revoke() {
	a.Revoked = true
}

func (a *RefreshToken) SetExpiration(expiresIn time.Duration) {
	a.ExpiresIn = int(time.Now().Add(expiresIn).Unix())
}

func (a *RefreshToken) SetIssuedTimeForNow() {
	a.IssuedAt = int(time.Now().Unix())
}
