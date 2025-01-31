package controllers

import (
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/servicecontexts"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthorizationController struct {
	authorizationService services.IAuthorizationService
	consentService       services.IConsentService
	consentEndpoint      string
}

func NewAuthorizationController(
	authorizationService services.IAuthorizationService,
	consentService services.IConsentService,
	consentEndpoint string,
) AuthorizationController {
	return AuthorizationController{
		authorizationService: authorizationService,
		consentService:       consentService,
		consentEndpoint:      consentEndpoint,
	}
}

// TODO: Session stores, user login redirection, etc.
func (ac *AuthorizationController) Authorize(c *gin.Context) {
	ctx := servicecontexts.NewAuthContext(c.Request.Context())

	//TODO: Investigate why pointer is throwing an error
	authInput := new(inputs.AuthorizationInput)
	if err := c.ShouldBindQuery(authInput); err != nil {
		//TODO: Handle error properly with redirect
		handleParseError(c, err, *authInput)
		return
	}

	session := sessions.Default(c)
	userID := session.Get("user_id")
	//TODO: First check if client exists
	session.Set("client_id", authInput.GetClientID())

	consentExists, err := ac.consentService.ConsentForClientAndUserExists(
		ctx,
		authInput.GetClientID(),
		userID.(string),
	)

	if err != nil {
		redirectURI := fmt.Sprintf("%s?error=internal_error&error_description=Internal server error", authInput.GetRedirectURI())
		logrus.Debugf("Redirecting to %s", redirectURI)
		c.Redirect(
			http.StatusFound,
			redirectURI,
		)
		return
	}

	if !consentExists {
		redirectURI := ac.consentEndpoint + "?client_redirect_uri=" + authInput.GetRedirectURI() + "&auth_redirect_uri=" + authInput.GetRedirectURI()
		logrus.Debugf("Redirecting to %s", redirectURI)
		c.Redirect(
			http.StatusFound,
			redirectURI,
		)
		return
	}

	ctx.UserID = userID.(string)
	output, err := ac.authorizationService.AuthorizeClient(ctx, authInput)

	//TODO: Handle error properly, depends on which error is returned
	if err != nil {
		//TODO: It can't be that way, we need to do proper errors and errors description
		params := fmt.Sprintf("?error=%s&error_description=%s", err, err)
		uri := authInput.GetRedirectURI()
		c.Redirect(
			http.StatusFound,
			uri+params,
		)
		return
	}

	params := fmt.Sprintf("?code=%s&state=%s", output.GetCode(), output.GetState())
	c.Redirect(
		http.StatusFound,
		authInput.RedirectURI+params,
	)
}
