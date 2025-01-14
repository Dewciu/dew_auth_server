package handlers

type Handlers struct {
	AuthorizationCodeGrantHandler IAuthorizationCodeGrantHandler
	AuthorizationHandler          IAuthorizationHandler
}
