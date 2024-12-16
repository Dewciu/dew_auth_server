package inputs

var _ IAccessTokenInput = new(RefreshTokenGrantInput)
var _ IAccessTokenInput = new(AuthorizationCodeGrantInput)

type IAccessTokenInput interface {
	GetGrantType() string
	GetClientID() string
	GetClientSecret() string
}

// All clients are confidential
type AccessTokenInput struct {
	GrantType    string `form:"grant_type" name:"grant_type" binding:"required"`
	ClientID     string `form:"client_id" name:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" name:"client_secret" binding:"required"`
}

func (i AccessTokenInput) GetGrantType() string {
	return i.GrantType
}

func (i AccessTokenInput) GetClientID() string {
	return i.ClientID
}

func (i AccessTokenInput) GetClientSecret() string {
	return i.ClientSecret
}

type RefreshTokenGrantInput struct {
	AccessTokenInput
	RefreshToken string `form:"refresh_token" name:"refresh_token" binding:"required"`
}

type AuthorizationCodeGrantInput struct {
	AccessTokenInput
	RedirectURI  string `form:"redirect_uri" name:"redirect_uri" binding:"required,url"`
	Code         string `form:"code" name:"code" binding:"required"`
	CodeVerifier string `form:"code_verifier" name:"code_verifier" binding:"required,min=43,max=128"`
}
