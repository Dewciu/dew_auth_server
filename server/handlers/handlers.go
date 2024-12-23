package handlers

type Handlers struct {
	AuthorizationCodeGrantHandler IAuthorizationCodeGrantHandler
	RegisterHandler               IRegisterHandler
	AuthorizationHandler          IAuthorizationHandler
}
