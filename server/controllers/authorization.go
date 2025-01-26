package controllers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/servicecontexts"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthorizationController struct {
	authorizationService services.IAuthorizationService
	sessionService       services.ISessionService
	consentService       services.IConsentService
}

func NewAuthorizationController(
	authorizationService services.IAuthorizationService,
	sessionService services.ISessionService,
	consentService services.IConsentService,
) AuthorizationController {
	return AuthorizationController{
		authorizationService: authorizationService,
		sessionService:       sessionService,
		consentService:       consentService,
	}
}

// TODO: Session stores, user login redirection, etc.
func (ac *AuthorizationController) Authorize(c *gin.Context) {
	loginRedirectEndpoint := "/oauth2/login"
	ctx := servicecontexts.NewAuthContext(c.Request.Context())

	//TODO: Investigate why pointer is throwing an error
	authInput := new(inputs.AuthorizationInput)
	if err := c.ShouldBindQuery(authInput); err != nil {
		//TODO: Handle error properly with redirect
		handleParseError(c, err, *authInput)
		return
	}

	cookies := c.Request.Cookies()

	sessionID := ac.getSessionID(cookies)
	escapedRedirectURI := url.QueryEscape(c.Request.RequestURI)

	if sessionID == "" {
		c.Redirect(http.StatusFound, loginRedirectEndpoint+"?client_id="+authInput.GetClientID()+"&redirect_uri="+escapedRedirectURI)
		return
	}

	session, err := ac.sessionService.RetrieveValidSession(ctx, sessionID)

	if err != nil {
		redirectURI := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s", loginRedirectEndpoint, authInput.GetClientID(), escapedRedirectURI)
		logrus.Debugf("Redirecting to %s", redirectURI)
		c.Redirect(http.StatusFound, redirectURI)
		return
	}

	consentExists, err := ac.consentService.ConsentForClientAndUserExists(
		ctx,
		authInput.GetClientID(),
		session.UserID.String(),
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
		redirectURI := fmt.Sprintf("%s?error=consent_required&error_description=Consent is required", authInput.GetRedirectURI())
		logrus.Debugf("Redirecting to %s", redirectURI)
		c.Redirect(
			http.StatusFound,
			redirectURI,
		)
		return
	}

	ctx.SessionID = sessionID
	ctx.UserID = session.UserID.String()

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

func (ac *AuthorizationController) getSessionID(cookies []*http.Cookie) string {
	sessionID := ""
	for _, cookie := range cookies {
		if cookie.Name == "session_id" {
			sessionID = cookie.Value
			break
		}
	}
	return sessionID
}
