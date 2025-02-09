package cachemodels

import (
	"time"

	"github.com/dewciu/dew_auth_server/server/cacheerrors"
	"github.com/dewciu/dew_auth_server/server/constants"
)

// AccessToken represents the structure of an access token used for authentication.
type AccessToken struct {
	Token     string              `json:"access_token"`  // Token is the actual access token string.
	Scopes    string              `json:"scopes"`        // Scope defines the permissions granted by the token.
	ClientID  string              `json:"client_id"`     // ClientID is the identifier of the client that requested the token.
	UserID    string              `json:"user_id"`       // UserID is the identifier of the user to whom the token was issued.
	TokenType constants.TokenType `json:"token_type"`    // TokenType specifies the type of the token (e.g., Bearer).
	ExpiresIn int                 `json:"exp"`           // ExpiresIn is the duration in seconds for which the token is valid.
	IssuedAt  int                 `json:"iat"`           // IssuedAt is the timestamp when the token was issued.
	NotBefore int                 `json:"nbf"`           // NotBefore is the timestamp before which the token is not valid.
	Audience  string              `json:"aud,omitempty"` // Audience specifies the intended recipients of the token.
	Subject   string              `json:"sub,omitempty"` // Subject identifies the principal that is the subject of the token.
	Issuer    string              `json:"iss,omitempty"` // Issuer identifies the entity that issued the token.
}

func NewBearerAccessToken(
	token string,
	scopes string,
	clientID string,
	userID string,
) (*AccessToken, error) {

	accessToken := &AccessToken{
		Token:     token,
		Scopes:    scopes,
		ClientID:  clientID,
		UserID:    userID,
		TokenType: constants.TokenTypeBearer,
	}

	if err := accessToken.Validate(); err != nil {
		return nil, err
	}

	return accessToken, nil
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
	return nil
}

func (a *AccessToken) SetAudience(audience string) {
	a.Audience = audience
}

func (a *AccessToken) SetSubject(subject string) {
	a.Subject = subject
}

func (a *AccessToken) SetIssuer(issuer string) {
	a.Issuer = issuer
}

func (a *AccessToken) SetExpiration(expiresIn time.Duration) {
	a.ExpiresIn = int(time.Now().Add(expiresIn).Unix())
}

func (a *AccessToken) SetIssuedTimeForNow() {
	a.IssuedAt = int(time.Now().Unix())
}

func (a *AccessToken) SetNotBeforeForNow() {
	a.NotBefore = int(time.Now().Unix())
}
