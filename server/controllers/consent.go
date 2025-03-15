package controllers

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/services"
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
	template *template.Template,
	clientService services.IClientService,
	consentService services.IConsentService,
	authorizeEndpoint string,
) ConsentController {
	return ConsentController{
		tmpl:              template,
		clientService:     clientService,
		consentService:    consentService,
		authorizeEndpoint: authorizeEndpoint,
	}
}

func (cc *ConsentController) ConsentHandler(c *gin.Context) {
	session := appcontext.MustGetSession(c.Request.Context())
	clientID := session.Get("client_id").(string)
	authRedirectURI := session.Get("auth_redirect_uri").(string)
	clientRedirectURI := session.Get("client_redirect_uri").(string)

	if clientID == "" || authRedirectURI == "" || clientRedirectURI == "" {
		logrus.WithFields(logrus.Fields{
			"client_id":           clientID,
			"auth_redirect_uri":   authRedirectURI,
			"client_redirect_uri": clientRedirectURI,
		}).Error("Missing required session parameters for consent")

		c.JSON(http.StatusBadRequest, gin.H{
			"error":             oautherrors.ErrInvalidRequest,
			"error_description": "Required session parameters are missing",
		})
		c.Abort()
		return
	}

	client, err := cc.clientService.CheckIfClientExistsByID(c.Request.Context(), clientID)
	if err != nil {
		logrus.WithError(err).Error("Error retrieving client for consent")
		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrServerError, "Internal server error")
		return
	}

	if client == nil {
		logrus.WithField("client_id", clientID).Error("Client not found for consent")
		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrInvalidClient, "Client not found")
		return
	}

	if !strings.Contains(authRedirectURI, cc.authorizeEndpoint) {
		logrus.WithFields(logrus.Fields{
			"redirect_uri":       authRedirectURI,
			"authorize_endpoint": cc.authorizeEndpoint,
		}).Error("Invalid redirect URI for consent")

		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrInvalidRequest, "Invalid redirect URI")
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
		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrInvalidRequest, "Method not allowed")
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
		logrus.WithError(err).Error("Failed to parse consent form")
		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrInvalidRequest, "Invalid form submission")
		return
	}

	scopes := c.Request.Form.Get("scopes")
	if scopes == "" {
		logrus.Error("Scopes missing in consent form")
		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrInvalidScope, "Scopes are required")
		return
	}

	consent := c.Request.Form.Get("consent")
	if consent == "" {
		logrus.Error("Consent decision missing in form")
		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrInvalidRequest, "Consent decision is required")
		return
	}

	logrus.WithField("consent", consent).Debug("Consent decision received")

	session, ok := appcontext.GetSession(c.Request.Context())

	if !ok {
		logrus.Error("Failed to get session from context")
		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrServerError, "Internal server error")
		return
	}

	userID := session.Get("user_id").(string)

	if consent != "allow" {
		logrus.WithFields(logrus.Fields{
			"user_id":   userID,
			"client_id": clientID,
		}).Info("User denied consent")

		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrAccessDenied, "Consent denied by user")
		return
	}

	_, err = cc.consentService.GrantConsentForClientAndUser(
		c.Request.Context(),
		clientID,
		userID,
		scopes,
	)

	if err != nil {
		logrus.WithError(err).Error("Failed to grant consent")
		cc.redirectWithError(c, clientRedirectURI, oautherrors.ErrServerError, "Failed to record consent")
		return
	}

	// Success - redirect back to authorization flow
	logrus.WithFields(logrus.Fields{
		"user_id":      userID,
		"client_id":    clientID,
		"redirect_uri": authRedirectURI,
	}).Info("Consent granted, continuing authorization flow")

	c.Redirect(http.StatusFound, authRedirectURI)
}

func (cc *ConsentController) redirectWithError(c *gin.Context, redirectURI string, errorType oautherrors.OAuthErrorType, errorDescription string) {
	redirectURI = fmt.Sprintf("%s?error=%s&error_description=%s",
		redirectURI,
		url.QueryEscape(string(errorType)),
		url.QueryEscape(errorDescription))

	logrus.WithFields(logrus.Fields{
		"redirect_uri":      redirectURI,
		"error_type":        errorType,
		"error_description": errorDescription,
	}).Debug("Redirecting from consent with error")

	c.Redirect(
		http.StatusFound,
		redirectURI,
	)
}
