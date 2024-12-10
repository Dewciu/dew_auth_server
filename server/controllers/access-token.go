package controllers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"
)

type AccessTokenController struct {
	service services.IAccessTokenService
}

func NewAccessTokenController(service services.IAccessTokenService) AccessTokenController {
	return AccessTokenController{
		service: service,
	}
}

func (atc AccessTokenController) Issue(c *gin.Context) {
	var commonInput inputs.AccessTokenInput
	if err := c.ShouldBind(&commonInput); err != nil {
		logrus.WithError(err).Error("Failed to parse common access token input")

		// Check if it's a validation error
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			c.JSON(http.StatusBadRequest, outputs.ValidationErrorResponse(
				string(constants.InvalidRequest),
				"There are validation errors in your request.",
				ve,
				commonInput,
			))
			return
		}

		// Not a validation error, just a generic parse error
		c.JSON(http.StatusBadRequest, outputs.ErrorResponse(
			string(constants.InvalidRequest),
			fmt.Sprintf("Unable to parse access token request: %v", err),
		))
		return
	}

	grantType := constants.GrantType(c.PostForm("grant_type"))
	switch grantType {
	case constants.AuthorizationCode:
		var authCodeGrantInput inputs.AuthorizationCodeGrantInput
		if err := c.ShouldBind(&authCodeGrantInput); err != nil {
			logrus.WithError(err).Error("Failed to parse authorization code grant input")

			var ve validator.ValidationErrors
			if errors.As(err, &ve) {
				c.JSON(http.StatusBadRequest, outputs.ValidationErrorResponse(
					string(constants.InvalidGrantError),
					"Invalid authorization code grant parameters.",
					ve,
					authCodeGrantInput,
				))
				return
			}

			c.JSON(http.StatusBadRequest, outputs.ErrorResponse(
				string(constants.InvalidGrantError),
				fmt.Sprintf("Invalid authorization code grant parameters: %v", err),
			))
			return
		}
		// TODO: Add logic to process authorization code grant

	case constants.RefreshToken:
		var refreshTokenGrantInput inputs.RefreshTokenGrantInput
		if err := c.ShouldBind(&refreshTokenGrantInput); err != nil {
			logrus.WithError(err).Error("Failed to parse refresh token grant input")

			var ve validator.ValidationErrors
			if errors.As(err, &ve) {
				c.JSON(http.StatusBadRequest, outputs.ValidationErrorResponse(
					string(constants.InvalidGrantError),
					"Invalid refresh token grant parameters.",
					ve,
					refreshTokenGrantInput,
				))
				return
			}

			c.JSON(http.StatusBadRequest, outputs.ErrorResponse(
				string(constants.InvalidGrantError),
				fmt.Sprintf("Invalid refresh token grant parameters: %v", err),
			))
			return
		}
		// TODO: Add logic to process refresh token grant

	default:
		err := fmt.Errorf("unsupported grant type: %s", grantType)
		logrus.WithField("grant_type", grantType).Error("Received invalid grant type")
		c.JSON(http.StatusBadRequest, outputs.ErrorResponse(
			string(constants.UnsupportedGrantType),
			err.Error(),
		))
	}
}
