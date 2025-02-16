package outputs

import "github.com/dewciu/dew_auth_server/server/cachemodels"

type RefreshTokenOutput struct {
	Active bool `json:"active"`
	cachemodels.RefreshToken
}
