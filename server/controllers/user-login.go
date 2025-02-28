package controllers

import (
	"html/template"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type UserLoginController struct {
	tmpl           *template.Template
	userService    services.IUserService
	consentService services.IConsentService
}

func NewUserLoginController(
	templatePath string,
	userService services.IUserService,
	consentService services.IConsentService,
) UserLoginController {
	return UserLoginController{
		tmpl:           template.Must(template.ParseFiles(templatePath + "/login-user.html")),
		userService:    userService,
		consentService: consentService,
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
	authRedirectURI := c.Query("redirect_uri")
	if authRedirectURI == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Redirect URI is required"})
		return
	}
	session := sessions.Default(c)
	if session.Get("user_id") != nil {
		c.Redirect(http.StatusFound, authRedirectURI)
		return
	}
	lc.tmpl.Execute(c.Writer, map[string]string{"RedirectURI": authRedirectURI})
}

func (lc *UserLoginController) handlePost(c *gin.Context) {
	authRedirectURI := c.Query("redirect_uri")

	if authRedirectURI == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Redirect URI is required"})
		return
	}

	err := c.Request.ParseForm()
	if err != nil {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Invalid form submission"})
		return
	}

	email := c.Request.Form.Get("email")
	password := c.Request.Form.Get("password")

	errRet := map[string]string{
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

	session := sessions.Default(c)
	session.Set("user_id", user.ID.String())

	if err := session.Save(); err != nil {
		errRet["Error"] = err.Error()
		lc.tmpl.Execute(c.Writer, errRet)
		return
	}

	lc.tmpl.Execute(c.Writer, map[string]string{
		"Success":     "User logged in successfully!",
		"RedirectURI": authRedirectURI,
	})
}
