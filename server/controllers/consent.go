package controllers

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type ConsentController struct {
	tmpl           *template.Template
	clientService  services.IClientService
	consentService services.IConsentService
}

func NewConsentController(
	templatePath string,
	clientService services.IClientService,
	consentService services.IConsentService,
) ConsentController {
	return ConsentController{
		tmpl:           template.Must(template.ParseFiles(templatePath + "/consent.html")),
		clientService:  clientService,
		consentService: consentService,
	}
}

func (cc *ConsentController) ConsentHandler(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet:
		cc.handleGet(c)
	case http.MethodPost:
		cc.handlePost(c)
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	}
}

func (cc *ConsentController) handleGet(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")

	//TODO: Refactor those also in other controllers
	if clientID == "" {
		cc.tmpl.Execute(c.Writer, map[string]string{"Error": "Client ID is required"})
		return
	}
	if redirectURI == "" {
		cc.tmpl.Execute(c.Writer, map[string]string{"Error": "Redirect URI is required"})
		return
	}

	client, err := cc.clientService.CheckIfClientExistsByID(
		c.Request.Context(),
		clientID,
	)

	//TODO: Do checking if client is really not found instead of some other error
	if err != nil {
		cc.tmpl.Execute(c.Writer, map[string]string{"Error": "Unable to find client"})
		return
	}

	scopes := strings.Split(client.Scopes, ",")

	cc.tmpl.Execute(c.Writer, map[string]interface{}{
		"ClientName":  client.Name,
		"Scopes":      scopes,
		"RedirectURI": redirectURI,
		"ClientID":    clientID,
	})
}

func (cc *ConsentController) handlePost(c *gin.Context) {
	err := c.Request.ParseForm()

	if err != nil {
		cc.tmpl.Execute(c.Writer, map[string]string{"Error": "Invalid form submission"})
		return
	}

	scopes := c.Request.Form.Get("scopes")
	consent := c.Request.Form.Get("consent")
	logrus.Debugf("Consent: %s", consent)

	clientID := c.Query("client_id")
	authRedirectURI := c.Query("redirect_uri")

	//TODO: Consider aborting if clientID or redirectURI is empty
	if clientID == "" {
		cc.tmpl.Execute(c.Writer, map[string]string{"Error": "Client ID is required"})
		return
	}

	if authRedirectURI == "" {
		cc.tmpl.Execute(c.Writer, map[string]string{"Error": "Redirect URI is required"})
		return
	}

	if scopes == "" {
		cc.tmpl.Execute(c.Writer, map[string]string{"Error": "Scopes are required"})
		return
	}

	session := sessions.Default(c)
	userID := session.Get("user_id").(string)

	if consent != "allow" {
		logrus.Debugf("Redirecting to %s", authRedirectURI)
		c.Redirect(http.StatusFound, authRedirectURI)
		return
	}

	_, err = cc.consentService.GrantConsentForClientAndUser(
		c.Request.Context(),
		clientID,
		userID,
		scopes,
	)

	if err != nil {
		cc.tmpl.Execute(c.Writer, map[string]string{"Error": "Unable to create consent"})
		return
	}

	logrus.Debugf("Redirecting to %s", authRedirectURI)
	c.Redirect(http.StatusFound, authRedirectURI)
}
