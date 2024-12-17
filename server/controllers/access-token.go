package controllers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/handlers"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"
)

type AccessTokenController struct {
	authCodeGrantHandler handlers.IAuthorizationCodeGrantHandler
}

func NewAccessTokenController(authCodeGrantHandler handlers.IAuthorizationCodeGrantHandler) AccessTokenController {
	return AccessTokenController{
		authCodeGrantHandler: authCodeGrantHandler,
	}
}

func (atc *AccessTokenController) Issue(c *gin.Context) {
	var commonInput inputs.AccessTokenInput
	if err := c.ShouldBind(&commonInput); err != nil {
		handleParseError(c, err, commonInput)
		return
	}

	grantType := constants.GrantType(c.PostForm("grant_type"))
	switch grantType {
	case constants.AuthorizationCode:
		atc.handleAuthorizationCodeGrant(c)
	case constants.RefreshToken:
		atc.handleRefreshTokenGrant(c)
	default:
		handleUnsupportedGrantType(c, grantType)
	}
}

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

func (atc AccessTokenController) handleAuthorizationCodeGrant(c *gin.Context) {
	var authCodeGrantInput inputs.AuthorizationCodeGrantInput
	if err := c.ShouldBind(&authCodeGrantInput); err != nil {
		handleGrantParseError(c, err, authCodeGrantInput, "authorization code")
		return
	}

	output, err := atc.authCodeGrantHandler.Handle(authCodeGrantInput)
	if err != nil {
		logrus.WithError(err).Error("Failed to handle authorization code grant")
		c.JSON(http.StatusInternalServerError, outputs.ErrorResponse(
			string(constants.ServerError),
			"Failed to handle authorization code grant.",
		))
		return
	}

	c.JSON(http.StatusCreated, output)
}

func (atc AccessTokenController) handleRefreshTokenGrant(c *gin.Context) {
	var refreshTokenGrantInput inputs.RefreshTokenGrantInput
	if err := c.ShouldBind(&refreshTokenGrantInput); err != nil {
		handleGrantParseError(c, err, refreshTokenGrantInput, "refresh token")
		return
	}

	// TODO: Add logic to process refresh token grant
}

func handleGrantParseError(c *gin.Context, err error, input interface{}, grantType string) {
	logrus.WithError(err).Errorf("Failed to parse %s grant input", grantType)

	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		c.JSON(http.StatusBadRequest, outputs.ValidationErrorResponse(
			string(constants.InvalidGrantError),
			fmt.Sprintf("Invalid %s grant parameters.", grantType),
			ve,
			input,
		))
		return
	}

	c.JSON(http.StatusBadRequest, outputs.ErrorResponse(
		string(constants.InvalidGrantError),
		fmt.Sprintf("Invalid %s grant parameters: %v", grantType, err),
	))
}

func handleUnsupportedGrantType(c *gin.Context, grantType constants.GrantType) {
	err := fmt.Errorf("unsupported grant type: %s", grantType)
	logrus.WithField("grant_type", grantType).Error("Received invalid grant type")
	c.JSON(http.StatusBadRequest, outputs.ErrorResponse(
		string(constants.UnsupportedGrantType),
		err.Error(),
	))
}
