package outputs

import (
	"github.com/dewciu/dew_auth_server/server/cachemodels"
)

type AccessTokenOutput struct {
	cachemodels.AccessToken
	Active bool `json:"active"`
}

type AuthorizationCodeGrantOutput struct {
	AccessTokenOutput
	RefreshToken string `json:"refresh_token"`
}
