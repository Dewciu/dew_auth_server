package middleware

import (
	"errors"

	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/dewciu/dew_auth_server/server/utils"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
)

func AuthorizeClientBasic(
	clientService services.IClientService,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		authHeader := c.Request.Header.Get("authorization")
		if authHeader == "" {
			e := oautherrors.NewOAuthUnauthorizedClientError(
				errors.New("authorization header is required"),
			)
			c.JSON(ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, e))
			c.Abort()
			return
		}

		clientID, secret, err := utils.GetCredentialsFromBasicAuthHeader(authHeader)
		if err != nil {
			e := oautherrors.NewOAuthUnauthorizedClientError(err)
			c.JSON(ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, e))
			c.Abort()
			return
		}

		client, err := clientService.VerifyClient(ctx, clientID, secret)
		if err != nil {
			msg := errors.New("an error occurred while verifying client")
			if _, ok := err.(serviceerrors.ClientNotFoundError); ok {
				msg = errors.New("client not found")
			}
			if _, ok := err.(serviceerrors.InvalidClientSecretError); ok {
				msg = errors.New("invalid client secret")
			}
			e := oautherrors.NewOAuthUnauthorizedClientError(msg)
			c.JSON(ginerr.NewErrorResponseFrom(ginerr.DefaultErrorRegistry, ctx, e))
			c.Abort()
			return
		}

		c.Set("client", client)
		c.Next()
	}
}
