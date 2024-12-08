package controllers

import (
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-gonic/gin"
)

type AccessTokenController struct {
	service services.IAccessTokenService
}

func NewAccessTokenController(service services.IAccessTokenService) AccessTokenController {
	return AccessTokenController{
		service: service,
	}
}

func (atc *AccessTokenController) Issue(c *gin.Context) {

}
