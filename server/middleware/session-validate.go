package middleware

import (
	"net/http"
	"net/url"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func SessionValidate(loginEndpoint string) gin.HandlerFunc {
	return func(c *gin.Context) {
		escapedRedirectURI := url.QueryEscape(c.Request.RequestURI)

		session := sessions.Default(c)
		userID := session.Get("user_id")

		if userID == nil {
			logrus.WithFields(logrus.Fields{
				"request_uri": c.Request.RequestURI,
				"endpoint":    loginEndpoint,
			}).Debug("User session not found or expired")

			c.Redirect(
				http.StatusFound,
				loginEndpoint+"?redirect_uri="+escapedRedirectURI,
			)
			c.Abort()
			return
		}

		ctx := c.Request.Context()
		c.Request = c.Request.WithContext(
			appcontext.WithUserID(ctx, userID.(string)),
		)

		c.Request = c.Request.WithContext(
			appcontext.WithSession(ctx, session),
		)

		c.Next()
	}
}
