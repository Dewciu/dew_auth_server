package server

type Endpoints struct {
	OAuth2Token          string
	OAuth2Revoke         string
	OAuth2Introspect     string
	OAuth2Authorize      string
	OAuth2RegisterClient string
	Oauth2RegisterUser   string
	OAuth2Login          string
	OAuth2Consent        string
}

var AllEndpoints = Endpoints{
	OAuth2Token:          "/oauth2/token",
	OAuth2Revoke:         "/oauth2/revoke",
	OAuth2Introspect:     "/oauth2/introspect",
	OAuth2Authorize:      "/oauth2/authorize",
	OAuth2RegisterClient: "/oauth2/register-client",
	Oauth2RegisterUser:   "/oauth2/register-user",
	OAuth2Login:          "/oauth2/login",
	OAuth2Consent:        "/oauth2/consent",
}
