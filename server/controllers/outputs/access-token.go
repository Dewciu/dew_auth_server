package outputs

var _ IAccessTokenOutput = new(AuthorizationCodeGrantOutput)

type IAccessTokenOutput interface {
	GetAccessToken() string
	GetTokenType() string
	GetExpiresIn() int
	GetScope() string
}

type AccessTokenOutput struct {
	AccessToken string `json:"access_token" name:"access_token" binding:"required"`
	TokenType   string `json:"token_type" name:"token_type" binding:"required"`
	ExpiresIn   int    `json:"expires_in" name:"expires_in" binding:"required"`
	Scope       string `json:"scope" name:"scope" binding:"required"`
}

func (i AccessTokenOutput) GetAccessToken() string {
	return i.AccessToken
}

func (i AccessTokenOutput) GetTokenType() string {
	return i.TokenType
}

func (i AccessTokenOutput) GetExpiresIn() int {
	return i.ExpiresIn
}

func (i AccessTokenOutput) GetScope() string {
	return i.Scope
}

type AuthorizationCodeGrantOutput struct {
	AccessTokenOutput
	RefreshToken string `form:"refresh_token" name:"refresh_token" binding:"required"`
}
