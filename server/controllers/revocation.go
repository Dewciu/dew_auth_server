package controllers

import (
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
	"github.com/sirupsen/logrus"
)

type RevocationController struct {
	accessTokenService  services.IAccessTokenService
	refreshTokenService services.IRefreshTokenService
}

func NewRevocationController(
	accessTokenService services.IAccessTokenService,
	refreshTokenService services.IRefreshTokenService,
) RevocationController {
	return RevocationController{
		accessTokenService:  accessTokenService,
		refreshTokenService: refreshTokenService,
	}
}

func (r *RevocationController) Revoke(c *gin.Context) {
	ctx := c.Request.Context()
	client := c.MustGet("client").(*models.Client)

	revocationInput := inputs.IntrospectionRevocationInput{}
	if err := c.ShouldBindJSON(&revocationInput); err != nil {
		e := oautherrors.NewOAuthInputValidationError(err, revocationInput)
		c.JSON(ginerr.NewErrorResponse(ctx, e))
		return
	}

	switch revocationInput.TokenType {
	case string(constants.TokenTypeAccess):
		r.revokeAccessToken(c, client, &revocationInput)
	case string(constants.TokenTypeRefresh):
		r.revokeRefreshToken(c, client, &revocationInput)
	default:
		e := oautherrors.NewOAuthUnsupportedTokenTypeError(
			fmt.Errorf("token type '%s' is not supported for revocation", revocationInput.TokenType),
		)
		c.JSON(ginerr.NewErrorResponseFrom(
			ginerr.DefaultErrorRegistry, ctx, e,
		))
	}
}

func (r *RevocationController) revokeAccessToken(
	c *gin.Context,
	client *models.Client,
	revocationInput *inputs.IntrospectionRevocationInput,
) {
	ctx := c.Request.Context()
	accessToken, err := r.accessTokenService.GetTokenDetails(ctx, revocationInput.Token)
	if err != nil || accessToken == nil || accessToken.ClientID != client.ID.String() {
		logrus.WithFields(logrus.Fields{
			"token_type": revocationInput.TokenType,
			"client_id":  client.ID.String(),
			"has_error":  err != nil,
		}).Debug("Token revocation unsuccessful: token not found or invalid")

		// According to RFC 7009, for security purposes, the authorization server
		// should respond with HTTP 200 even when the token was invalid
		c.JSON(http.StatusOK, gin.H{
			"active": false,
		})
		return
	}

	err = r.accessTokenService.RevokeToken(ctx, accessToken)
	if err != nil {
		logrus.WithError(err).Error("Failed to revoke access token")
		e := oautherrors.NewOAuthInternalServerError(
			fmt.Errorf("failed to revoke access token: %w", err),
		)
		c.JSON(ginerr.NewErrorResponseFrom(
			ginerr.DefaultErrorRegistry, ctx, e,
		))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active": false,
	})
}

func (r *RevocationController) revokeRefreshToken(
	c *gin.Context,
	client *models.Client,
	revocationInput *inputs.IntrospectionRevocationInput,
) {
	ctx := c.Request.Context()
	refreshToken, err := r.refreshTokenService.GetTokenDetails(ctx, revocationInput.Token)
	if err != nil || refreshToken == nil || refreshToken.ClientID != client.ID.String() {
		logrus.WithFields(logrus.Fields{
			"token_type": revocationInput.TokenType,
			"client_id":  client.ID.String(),
			"has_error":  err != nil,
		}).Debug("Token revocation unsuccessful: token not found or invalid")

		// According to RFC 7009, for security purposes, the authorization server
		// should respond with HTTP 200 even when the token was invalid
		c.JSON(http.StatusOK, gin.H{
			"active": false,
		})
		return
	}

	err = r.refreshTokenService.RevokeToken(ctx, refreshToken)
	if err != nil {
		logrus.WithError(err).Error("Failed to revoke refresh token")
		e := oautherrors.NewOAuthInternalServerError(
			fmt.Errorf("failed to revoke refresh token: %w", err),
		)
		c.JSON(ginerr.NewErrorResponseFrom(
			ginerr.DefaultErrorRegistry, ctx, e,
		))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active": false,
	})
}
