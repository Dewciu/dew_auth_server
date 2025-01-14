package controllers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"
)

type Controllers struct {
	AccessTokenController    AccessTokenController
	AuthorizationController  AuthorizationController
	ClientRegisterController ClientRegisterController
	UserRegisterController   UserRegisterController
}

//TODO: Do something with it. We need to define better error handling.

func handleParseError(c *gin.Context, err error, input interface{}) {
	logrus.WithError(err).Error("Failed to parse common access token input")

	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		c.JSON(http.StatusBadRequest, outputs.ValidationErrorResponse(
			string(constants.InvalidRequest),
			"There are validation errors in your request.",
			ve,
			input,
		))
		return
	}

	c.JSON(http.StatusBadRequest, outputs.ErrorResponse(
		string(constants.InvalidRequest),
		fmt.Sprintf("Unable to parse access token request: %v", err),
	))
}
