package cachemodels

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
