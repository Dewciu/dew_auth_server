package outputs

import (
	"github.com/dewciu/dew_auth_server/server/cachemodels"
)

type AccessTokenOutput struct {
	Active bool `json:"active"`
	cachemodels.AccessToken
}

type AuthorizationCodeGrantOutput struct {
	AccessTokenOutput
	RefreshToken string `json:"refresh_token"`
}
