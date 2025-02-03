package cachemodels

import (
	"github.com/dewciu/dew_auth_server/server/cacheerrors"
)

// AuthorizationCode represents an issued authorization code in redis.
type AuthorizationCode struct {
	Code                string // Code is the actual authorization code
	UserID              string // UserID is the ID of the user that authorized the client
	ClientID            string // ClientID is the ID of the client that requested the authorization code
	RedirectURI         string // RedirectURI is the URI to redirect the user-agent to after authorization
	Scopes              string // comma separated scopes
	CodeChallenge       string // PKCE code challenge
	CodeChallengeMethod string // PKCE code challenge method
}

func NewAuthorizationCode(code, userID, clientID, redirectURI, scopes, codeChallenge, codeChallengeMethod string) (*AuthorizationCode, error) {
	authCode := &AuthorizationCode{
		Code:                code,
		UserID:              userID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	if err := authCode.Validate(); err != nil {
		return nil, err
	}

	return authCode, nil
}

// Validate checks for missing fields in the AuthorizationCode struct.
func (ac *AuthorizationCode) Validate() error {
	if ac.Code == "" {
		return &cacheerrors.MissingAuthorizationCodeError{}
	}
	if ac.UserID == "" {
		return &cacheerrors.MissingUserIDError{}
	}
	if ac.ClientID == "" {
		return &cacheerrors.MissingClientIDError{}
	}
	if ac.RedirectURI == "" {
		return &cacheerrors.MissingRedirectURIError{}
	}
	if ac.Scopes == "" {
		return &cacheerrors.MissingScopesError{}
	}
	if ac.CodeChallenge == "" {
		return &cacheerrors.MissingCodeChallengeError{}
	}
	if ac.CodeChallengeMethod == "" {
		return &cacheerrors.MissingCodeChallengeMethodError{}
	}
	return nil
}
