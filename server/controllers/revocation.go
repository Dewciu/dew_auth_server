package controllers

import (
	"errors"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
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
			errors.New("revoke endpoint does not support this token type"),
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
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_token",
			"error_description": "access token is invalid",
		})
		return
	}

	err = r.accessTokenService.RevokeToken(ctx, accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to revoke access token",
		})
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
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_token",
			"error_description": "refresh token is invalid",
		})
		return
	}

	err = r.refreshTokenService.RevokeToken(ctx, refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to revoke refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active": false,
	})
}
