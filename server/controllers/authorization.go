package controllers

import (
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/handlers"
	"github.com/gin-gonic/gin"
)

type AuthorizationController struct {
	authCodeHandler handlers.IAuthorizationHandler
}

func NewAuthorizationController(authCodeHandler handlers.IAuthorizationHandler) AuthorizationController {
	return AuthorizationController{
		authCodeHandler: authCodeHandler,
	}
}

// TODO: Session stores, user login redirection, etc.
func (ac *AuthorizationController) Authorize(c *gin.Context) {
	var authInput inputs.AuthorizationInput

	if err := c.ShouldBindQuery(&authInput); err != nil {
		handleParseError(c, err, authInput)
		return
	}

	// output, err := ac.authCodeHandler.Handle(authInput)
	// if err != nil {
	// 	logrus.WithError(err).Error("Failed to handle authorization request")
	// 	c.JSON(http.StatusInternalServerError, outputs.ErrorResponse(
	// 		string(constants.ServerError),
	// 		"Failed to handle authorization request.",
	// 	))
	// 	return
	// }

	// c.JSON(http.StatusOK, output)
}
