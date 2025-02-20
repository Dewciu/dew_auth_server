package controllers

import (
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/servicecontexts"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
	"github.com/sirupsen/logrus"
)

type AuthorizationController struct {
	authorizationService services.IAuthorizationService
	consentService       services.IConsentService
	clientService        services.IClientService
	consentEndpoint      string
}

func NewAuthorizationController(
	authorizationService services.IAuthorizationService,
	consentService services.IConsentService,
	clientService services.IClientService,
	consentEndpoint string,
) AuthorizationController {
	return AuthorizationController{
		authorizationService: authorizationService,
		consentService:       consentService,
		clientService:        clientService,
		consentEndpoint:      consentEndpoint,
	}
}

// TODO: Session stores, user login redirection, etc.
func (ac *AuthorizationController) Authorize(c *gin.Context) {
	ctx := servicecontexts.NewAuthContext(c.Request.Context())

	authInput := inputs.AuthorizationInput{}
	if err := c.ShouldBindQuery(&authInput); err != nil {
		e := oautherrors.NewOAuthInputValidationError(err, authInput)
		c.JSON(ginerr.NewErrorResponse(ctx, e))
		return
	}

	//TODO: Retrieve session from gin context
	session := sessions.Default(c)
	userID := session.Get("user_id").(string)

	client, err := ac.clientService.CheckIfClientExistsByID(
		c.Request.Context(),
		authInput.GetClientID(),
	)

	if err != nil {
		ac.redirectWithInternalServerErr(c, authInput.GetRedirectURI())
	}

	if client == nil {
		params := "?error=client does not exists&error_description=Invalid client id"
		uri := authInput.GetRedirectURI()
		c.Redirect(
			http.StatusFound,
			uri+params,
		)
		return
	}

	session.Set("client_id", authInput.GetClientID())
	session.Save()

	consentExists, err := ac.consentService.ConsentForClientAndUserExists(
		ctx,
		client.ID.String(),
		userID,
	)

	if err != nil {
		ac.redirectWithInternalServerErr(c, authInput.GetRedirectURI())
	}

	if !consentExists {
		session.Set("auth_redirect_uri", c.Request.RequestURI)
		session.Set("client_redirect_uri", authInput.GetRedirectURI())
		session.Save()
		logrus.Debugf("Redirecting to %s", ac.consentEndpoint)
		c.Redirect(
			http.StatusFound,
			ac.consentEndpoint,
		)
		return
	}

	ctx.UserID = userID
	ctx.Client = client
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

func (ac *AuthorizationController) redirectWithInternalServerErr(c *gin.Context, redirectURI string) {
	redirectURI = fmt.Sprintf("%s?error=internal_error&error_description=Internal server error", redirectURI)
	logrus.Debugf("Redirecting to %s", redirectURI)
	c.Redirect(
		http.StatusFound,
		redirectURI,
	)
}
