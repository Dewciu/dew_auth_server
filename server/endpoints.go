package server

type Endpoints struct {
	OAuth2Token     string
	OAuth2Authorize string
	RegisterClient  string
	RegisterUser    string
	OAuth2Login     string
	OAuth2Consent   string
}

var AllEndpoints = Endpoints{
	OAuth2Token:     "/oauth2/token",
	OAuth2Authorize: "/oauth2/authorize",
	RegisterClient:  "/register-client",
	RegisterUser:    "/register-user",
	OAuth2Login:     "/oauth2/login",
	OAuth2Consent:   "/oauth2/consent",
}
