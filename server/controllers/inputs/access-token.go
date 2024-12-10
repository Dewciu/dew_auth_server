package inputs

type AccessTokenInput struct {
	GrantType string `form:"grant_type" name:"grant_type" binding:"required"`
	ClientID  string `form:"client_id" name:"client_id" binding:"required"`
}

type RefreshTokenGrantInput struct {
	AccessTokenInput
	RefreshToken string `form:"refresh_token" name:"refresh_token" binding:"required"`
	ClientSecret string `form:"client_secret" name:"client_secret" binding:"required"`
}

type AuthorizationCodeGrantInput struct {
	AccessTokenInput
	Code         string `form:"code" name:"code" binding:"required"`
	RedirectURI  string `form:"redirect_uri" name:"redirect_uri" binding:"required,url"`
	CodeVerifier string `form:"code_verifier" name:"code_verifier" binding:"required,min=43,max=128"`
}
