package controllers

import (
	"errors"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/controllers/outputs"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
)

type IntrospectionController struct {
	accessTokenService  services.IAccessTokenService
	refreshTokenService services.IRefreshTokenService
}

func NewIntrospectionController(
	accessTokenService services.IAccessTokenService,
	refreshTokenService services.IRefreshTokenService,
) IntrospectionController {
	return IntrospectionController{
		accessTokenService:  accessTokenService,
		refreshTokenService: refreshTokenService,
	}
}

func (i *IntrospectionController) Introspect(c *gin.Context) {
	ctx := c.Request.Context()
	client := c.MustGet("client").(*models.Client)

	introspectionInput := inputs.IntrospectionRevocationInput{}
	if err := c.ShouldBindJSON(&introspectionInput); err != nil {
		e := oautherrors.NewOAuthInputValidationError(err, introspectionInput)
		c.JSON(ginerr.NewErrorResponse(ctx, e))
		return
	}

	switch introspectionInput.TokenType {
	case string(constants.TokenTypeAccess):
		i.introspectAccessToken(c, client, &introspectionInput)
	case string(constants.TokenTypeRefresh):
		i.introspectRefreshToken(c, client, &introspectionInput)
	default:
		e := oautherrors.NewOAuthUnsupportedTokenTypeError(
			errors.New("introspection endpoint does not support this token type"),
		)
		c.JSON(ginerr.NewErrorResponseFrom(
			ginerr.DefaultErrorRegistry, ctx, e,
		))
	}
}

func (i *IntrospectionController) introspectAccessToken(
	c *gin.Context,
	client *models.Client,
	introspectionInput *inputs.IntrospectionRevocationInput,
) {
	ctx := c.Request.Context()
	accessToken, err := i.accessTokenService.GetTokenDetails(ctx, introspectionInput.Token)
	if err != nil || accessToken == nil || accessToken.ClientID != client.ID.String() {
		c.JSON(http.StatusOK, gin.H{
			"active": false,
		})
		return
	}

	accessTokenOutput := outputs.AccessTokenOutput{
		Active:      true,
		AccessToken: *accessToken,
	}

	c.JSON(http.StatusOK, accessTokenOutput)
}

func (i *IntrospectionController) introspectRefreshToken(
	c *gin.Context,
	client *models.Client,
	introspectionInput *inputs.IntrospectionRevocationInput,
) {
	ctx := c.Request.Context()
	refreshToken, err := i.refreshTokenService.GetTokenDetails(ctx, introspectionInput.Token)
	if err != nil ||
		refreshToken == nil ||
		refreshToken.ClientID != client.ID.String() ||
		!refreshToken.IsActive() {
		c.JSON(http.StatusOK, gin.H{
			"active": false,
		})
		return
	}

	refreshTokenOutput := outputs.RefreshTokenOutput{
		Active:       true,
		RefreshToken: *refreshToken,
	}

	c.JSON(http.StatusOK, refreshTokenOutput)
}
