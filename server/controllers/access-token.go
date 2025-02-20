package controllers

import (
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
	"github.com/sirupsen/logrus"
)

type AccessTokenController struct {
	authCodeGrantService services.IGrantService
}

func NewAccessTokenController(authCodeGrantService services.IGrantService) AccessTokenController {
	return AccessTokenController{
		authCodeGrantService: authCodeGrantService,
	}
}

func (atc *AccessTokenController) Issue(c *gin.Context) {
	ctx := c.Request.Context()
	commonInput := inputs.AccessTokenInput{}
	if err := c.ShouldBind(&commonInput); err != nil {
		e := oautherrors.NewOAuthInputValidationError(err, commonInput)
		c.JSON(ginerr.NewErrorResponse(ctx, e))
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

func (atc AccessTokenController) handleAuthorizationCodeGrant(c *gin.Context) {
	ctx := c.Request.Context()
	authCodeGrantInput := inputs.AuthorizationCodeGrantInput{}
	if err := c.ShouldBind(&authCodeGrantInput); err != nil {
		e := oautherrors.NewOAuthInputValidationError(err, authCodeGrantInput)
		c.JSON(ginerr.NewErrorResponse(ctx, e))
		return
	}

	output, err := atc.authCodeGrantService.ObtainByAuthCode(ctx, authCodeGrantInput)
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
	ctx := c.Request.Context()
	refreshTokenGrantInput := inputs.RefreshTokenGrantInput{}
	if err := c.ShouldBind(&refreshTokenGrantInput); err != nil {
		e := oautherrors.NewOAuthInputValidationError(err, refreshTokenGrantInput)
		c.JSON(ginerr.NewErrorResponse(ctx, e))
		return
	}

	output, err := atc.authCodeGrantService.ObtainByRefreshToken(ctx, refreshTokenGrantInput, false)
	if err != nil {
		logrus.WithError(err).Error("Failed to handle refresh token grant")
		c.JSON(http.StatusInternalServerError, outputs.ErrorResponse(
			string(constants.ServerError),
			"Failed to handle refresh token grant.",
		))
		return
	}

	c.JSON(http.StatusCreated, output)
}

func handleUnsupportedGrantType(c *gin.Context, grantType constants.GrantType) {
	err := fmt.Errorf("unsupported grant type: %s", grantType)
	logrus.WithField("grant_type", grantType).Error("Received invalid grant type")
	c.JSON(http.StatusBadRequest, outputs.ErrorResponse(
		string(constants.UnsupportedGrantType),
		err.Error(),
	))
}
