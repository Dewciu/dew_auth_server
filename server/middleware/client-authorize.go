package middleware

import (
	"net/http"

	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/utils"
	"github.com/gin-gonic/gin"
)

func AuthorizeClientBasic(
	clientService services.IClientService,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		authHeader := c.Request.Header.Get("authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header is required"})
			c.Abort()
			return
		}

		clientID, secret, err := utils.GetCredentialsFromBasicAuthHeader(authHeader)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		client, err := clientService.VerifyClientSecret(ctx, clientID, secret)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid client credentials"})
			c.Abort()
			return
		}

		c.Set("client", client)
		c.Next()
	}
}
