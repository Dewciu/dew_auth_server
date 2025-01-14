package controllers

import (
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/servicecontexts"
	"github.com/gin-gonic/gin"
)

type AuthorizationController struct {
	authorizationService services.IAuthorizationService
	sessionService       services.ISessionService
}

func NewAuthorizationController(
	authorizationService services.IAuthorizationService,
	sessionService services.ISessionService,

) AuthorizationController {
	return AuthorizationController{
		authorizationService: authorizationService,
		sessionService:       sessionService,
	}
}

// TODO: Session stores, user login redirection, etc.
func (ac *AuthorizationController) Authorize(c *gin.Context) {
	loginRedirectEndpoint := "/oauth/login"
	ctx := servicecontexts.NewAuthContext(c.Request.Context())

	//TODO: Investigate why pointer is throwing an error
	var authInput inputs.AuthorizationInput
	if err := c.ShouldBindQuery(&authInput); err != nil {
		//TODO: Handle error properly with redirect
		handleParseError(c, err, authInput)
		return
	}

	cookies := c.Request.Cookies()

	sessionID := ac.getSessionID(cookies)

	if sessionID == "" {
		c.Redirect(http.StatusFound, loginRedirectEndpoint)
		return
	}

	userID, err := ac.sessionService.GetUserIDFromSession(ctx, sessionID)

	if err != nil {
		c.Redirect(http.StatusFound, loginRedirectEndpoint)
		return
	}

	ctx.SessionID = sessionID
	ctx.UserID = userID

	output, err := ac.authorizationService.Handle(ctx, &authInput)

	//TODO: Handle error properly, depends on which error is returned
	if err != nil {
		//TODO: It can't be that way, we need to do proper errors and errors description
		params := fmt.Sprintf("?error=%s&error_description=%s", err, err)
		val := &authInput
		uri := val.RedirectURI
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
