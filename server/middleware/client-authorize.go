package middleware

import (
	"errors"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/dewciu/dew_auth_server/server/utils"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
	"github.com/sirupsen/logrus"
)

func AuthorizeClient(
	clientService services.IClientService,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		var clientID, clientSecret string
		var err error

		authHeader := c.Request.Header.Get("authorization")
		if authHeader != "" {
			clientID, clientSecret, err = utils.GetCredentialsFromBasicAuthHeader(authHeader)
			if err != nil {
				logrus.WithError(err).Debug("Failed to parse Authorization header")
			}
		}

		if clientID == "" || clientSecret == "" {
			clientID = c.PostForm("client_id")
			clientSecret = c.PostForm("client_secret")
		}

		if clientID == "" || clientSecret == "" {
			e := oautherrors.NewOAuthInvalidClientError(
				errors.New("client_id and client_secret are required"),
			)
			c.JSON(ginerr.NewErrorResponseFrom(
				ginerr.DefaultErrorRegistry, ctx, e,
			))
			c.Abort()
			return
		}

		client, err := clientService.VerifyClient(ctx, clientID, clientSecret)
		if err != nil {
			var code int
			var e any
			switch err.(type) {
			case serviceerrors.ClientNotFoundError:
				code, e = ginerr.NewErrorResponseFrom(
					ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInvalidClientError(err),
				)
			case serviceerrors.InvalidClientSecretError:
				code, e = ginerr.NewErrorResponseFrom(
					ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthUnauthorizedClientError(err),
				)
			default:
				code, e = ginerr.NewErrorResponseFrom(
					ginerr.DefaultErrorRegistry, ctx, oautherrors.NewOAuthInternalServerError(err),
				)
			}
			c.JSON(code, e)
			c.Abort()
			return
		}

		c.Request = c.Request.WithContext(
			appcontext.WithClient(ctx, client),
		)
		c.Next()
	}
}
