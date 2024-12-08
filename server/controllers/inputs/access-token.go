package inputs

type AccessTokenInput struct {
	GrantType string `json:"grant_type" binding:"required"`
	ClientID  string `json:"client_id" binding:"required"`
}

type RefreshTokenGrantInput struct {
	AccessTokenInput
	RefreshToken string `json:"refresh_token" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
}

type AuthorizationCodeGrantInput struct {
	AccessTokenInput
	Code         string `json:"code" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
	CodeVerifier string `json:"code_verifier" binding:"required"`
}
