package controllers

import (
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
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
		e := oautherrors.NewOAuthUnsupportedGrantTypeError(
			fmt.Errorf("'%s' is not a valid grant type", grantType),
		)
		c.JSON(ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, e))
		return
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
		var e any
		var code int
		switch err.(type) {
		case serviceerrors.ClientNotFoundError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInvalidClientError(err))
		case serviceerrors.InvalidClientSecretError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInvalidClientError(err))
		case serviceerrors.InvalidAuthorizationCodeError, serviceerrors.InvalidPKCEVerifierError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInvalidGrantError(err))
		case serviceerrors.UnsupportedGrantTypeError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthUnsupportedGrantTypeError(err))
		case serviceerrors.UnsupportedResponseTypeError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthUnsupportedResponseTypeError(err))
		default:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInternalServerError(err))
		}

		logrus.WithError(err).Error("failed to handle authorization code grant")
		c.JSON(code, e)
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
		var e any
		var code int
		switch err.(type) {
		case serviceerrors.ClientNotFoundError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInvalidClientError(err))
		case serviceerrors.TokenNotFoundError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInvalidTokenError(err))
		case serviceerrors.InvalidClientSecretError, serviceerrors.ClientAuthorizationError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInvalidClientError(err))
		case serviceerrors.UnsupportedGrantTypeError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthUnsupportedGrantTypeError(err))
		case serviceerrors.UnsupportedResponseTypeError:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthUnsupportedResponseTypeError(err))
		default:
			code, e = ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInternalServerError(err))
		}

		logrus.WithError(err).Error("failed to handle refresh token grant")
		c.JSON(code, e)
		return
	}

	c.JSON(http.StatusCreated, output)
}
