package controllers

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type ConsentController struct {
	tmpl              *template.Template
	clientService     services.IClientService
	consentService    services.IConsentService
	authorizeEndpoint string
}

func NewConsentController(
	templatePath string,
	clientService services.IClientService,
	consentService services.IConsentService,
	authorizeEndpoint string,
) ConsentController {
	return ConsentController{
		tmpl:              template.Must(template.ParseFiles(templatePath + "/consent.html")),
		clientService:     clientService,
		consentService:    consentService,
		authorizeEndpoint: authorizeEndpoint,
	}
}

func (cc *ConsentController) ConsentHandler(c *gin.Context) {

	session := sessions.Default(c)
	clientID := session.Get("client_id").(string)
	authRedirectURI := session.Get("auth_redirect_uri").(string)
	clientRedirectURI := session.Get("client_redirect_uri").(string)

	if clientID == "" || authRedirectURI == "" || clientRedirectURI == "" {
		c.AbortWithError(
			http.StatusBadRequest,
			errors.New("client ID, auth redirect URI, and client redirect URI are required"),
		)
		return
	}

	client, err := cc.clientService.CheckIfClientExistsByID(c.Request.Context(), clientID)

	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if client == nil {
		c.AbortWithError(http.StatusNotFound, errors.New("client not found"))
		return
	}

	if !strings.Contains(authRedirectURI, cc.authorizeEndpoint) {
		c.AbortWithError(http.StatusBadRequest, errors.New("invalid redirect URI"))
		return
	}

	switch c.Request.Method {
	case http.MethodGet:
		cc.tmpl.Execute(c.Writer, map[string]interface{}{
			"ClientName": client.Name,
			"Scopes":     strings.Split(client.Scopes, ","),
		})
	case http.MethodPost:
		cc.handlePost(c, authRedirectURI, clientRedirectURI, clientID)
	default:
		c.AbortWithError(http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (cc *ConsentController) handlePost(
	c *gin.Context,
	authRedirectURI string,
	clientRedirectURI string,
	clientID string,
) {
	err := c.Request.ParseForm()

	if err != nil {
		cc.tmpl.Execute(c.Writer, map[string]string{"Error": "Invalid form submission"})
		return
	}

	//TODO: Do advanced validation

	scopes := c.Request.Form.Get("scopes")

	if scopes == "" {
		c.AbortWithError(http.StatusBadRequest, errors.New("scopes are required"))
		return
	}

	consent := c.Request.Form.Get("consent")

	if consent == "" {
		c.AbortWithError(http.StatusBadRequest, errors.New("consent is required"))
		return
	}

	logrus.Debugf("Consent: %s", consent)

	session := sessions.Default(c)
	userID := session.Get("user_id").(string)

	if consent != "allow" {
		redirectURI := clientRedirectURI + "?error=consent_denied&error_description=Consent denied"
		logrus.Debugf("Redirecting to %s", redirectURI)
		c.Redirect(http.StatusFound, redirectURI)
		return
	}

	_, err = cc.consentService.GrantConsentForClientAndUser(
		c.Request.Context(),
		clientID,
		userID,
		scopes,
	)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, errors.New("failed to grant consent"))
		return
	}

	c.Redirect(http.StatusFound, authRedirectURI)
}
