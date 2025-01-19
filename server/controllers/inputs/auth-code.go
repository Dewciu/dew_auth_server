package inputs

var _ IAuthorizationInput = new(AuthorizationInput)

type IAuthorizationInput interface {
	GetClientID() string
	GetRedirectURI() string
	GetResponseType() string
	GetScope() string
	GetState() string
	GetCodeChallenge() string
	GetCodeChallengeMethod() string
}

type AuthorizationInput struct {
	ClientID            string `form:"client_id" binding:"required" name:"client_id"`
	RedirectURI         string `form:"redirect_uri" binding:"required,uri" name:"redirect_uri"`
	ResponseType        string `form:"response_type" binding:"required,oneof=code" name:"response_type"`
	Scope               string `form:"scope" binding:"required" name:"scope"`
	State               string `form:"state" binding:"required" name:"state"`
	CodeChallenge       string `form:"code_challenge" binding:"required" name:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method" binding:"required,oneof=S256 plain" name:"code_challenge_method"`
}

func (a AuthorizationInput) GetClientID() string {
	return a.ClientID
}

func (a AuthorizationInput) GetRedirectURI() string {
	return a.RedirectURI
}

func (a AuthorizationInput) GetResponseType() string {
	return a.ResponseType
}

func (a AuthorizationInput) GetScope() string {
	return a.Scope
}

func (a AuthorizationInput) GetState() string {
	return a.State
}

func (a AuthorizationInput) GetCodeChallenge() string {
	return a.CodeChallenge
}

func (a AuthorizationInput) GetCodeChallengeMethod() string {
	return a.CodeChallengeMethod
}
