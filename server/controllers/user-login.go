package controllers

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type UserLoginController struct {
	tmpl                   *template.Template
	defaultSessionDuration int
	userService            services.IUserService
	sessionService         services.ISessionService
	consentService         services.IConsentService
}

func NewUserLoginController(
	templatePath string,
	userService services.IUserService,
	sessionService services.ISessionService,
	consentService services.IConsentService,
) UserLoginController {
	//TODO: Session duration can be done as a configuration
	return UserLoginController{
		tmpl:                   template.Must(template.ParseFiles(templatePath + "/login-user.html")),
		defaultSessionDuration: 360,
		userService:            userService,
		sessionService:         sessionService,
		consentService:         consentService,
	}
}

func (lc *UserLoginController) LoginHandler(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet:
		lc.handleGet(c)
	case http.MethodPost:
		lc.handlePost(c)
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	}
}

func (lc *UserLoginController) handleGet(c *gin.Context) {
	clientID := c.Query("client_id")
	authRedirectURI := c.Query("redirect_uri")
	sessionExpired := c.Query("session_expired")

	if clientID == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Client ID is required"})
		return
	}
	if authRedirectURI == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Redirect URI is required"})
		return
	}
	lc.tmpl.Execute(c.Writer, map[string]string{"ClientID": clientID, "RedirectURI": authRedirectURI, "SessionExpired": sessionExpired})
}

func (lc *UserLoginController) handlePost(c *gin.Context) {
	err := c.Request.ParseForm()
	if err != nil {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Invalid form submission"})
		return
	}

	email := c.Request.Form.Get("email")
	password := c.Request.Form.Get("password")
	clientID := c.Query("client_id")
	authRedirectURI := c.Query("redirect_uri")

	if clientID == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Client ID is required"})
		return
	}
	if authRedirectURI == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Redirect URI is required"})
		return
	}

	errRet := map[string]string{
		"ClientID":    clientID,
		"RedirectURI": authRedirectURI,
	}

	if email == "" {
		errRet["Error"] = "Email is required"
		lc.tmpl.Execute(c.Writer, errRet)
		return
	}
	if password == "" {
		errRet["Error"] = "Password is required"
		return
	}

	userLoginInput := inputs.UserLoginInput{
		Email:    email,
		Password: password,
	}

	user, err := lc.userService.LoginUser(
		c.Request.Context(),
		userLoginInput,
	)

	if err != nil {
		errRet["Error"] = err.Error()
		lc.tmpl.Execute(c.Writer, errRet)
		return
	}

	session, err := lc.sessionService.CreateSession(
		c.Request.Context(),
		user.ID.String(),
		clientID,
		lc.defaultSessionDuration,
	)

	c.SetCookie(
		"session_id",
		session.ID.String(),
		lc.defaultSessionDuration,
		"/",
		"localhost",
		false,
		true,
	)

	if err != nil {
		errRet["Error"] = err.Error()
		lc.tmpl.Execute(c.Writer, errRet)
		return
	}

	consentExists, err := lc.consentService.ConsentForClientAndUserExists(
		c.Request.Context(),
		clientID,
		user.ID.String(),
	)

	if err != nil {
		logrus.WithError(err).Error("Error checking consent")
		errRet["Error"] = "Error checking consent"
		lc.tmpl.Execute(c.Writer, errRet)
		return
	}

	if consentExists {
		//TODO: Do something to retrieve default session cookie
		//TODO: Secure should be considered
		lc.tmpl.Execute(c.Writer, map[string]string{
			"Success":     "User logged in successfully!",
			"RedirectURI": authRedirectURI,
		})
	} else {
		escapedAuthRedirectUri := url.QueryEscape(authRedirectURI)
		redirectUri := fmt.Sprintf("/oauth2/consent?client_id=%s&redirect_uri=%s", clientID, escapedAuthRedirectUri)
		logrus.Debugf("Redirecting to %s", redirectUri)
		c.Redirect(http.StatusFound, redirectUri)
	}
}
