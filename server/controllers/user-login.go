package controllers

import (
	"html/template"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-gonic/gin"
)

type UserLoginController struct {
	tmpl           *template.Template
	userService    services.IUserService
	sessionService services.ISessionService
}

func NewUserLoginController(
	templatePath string,
	userService services.IUserService,
	sessionService services.ISessionService,
) UserLoginController {
	return UserLoginController{
		tmpl:           template.Must(template.ParseFiles(templatePath + "/login-form.html")),
		userService:    userService,
		sessionService: sessionService,
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
	if clientID == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Client ID is required"})
		return
	}
	lc.tmpl.Execute(c.Writer, map[string]string{"ClientID": clientID})
}

func (lc *UserLoginController) handlePost(c *gin.Context) {
	err := c.Request.ParseForm()
	if err != nil {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Invalid form submission"})
		return
	}

	email := c.Request.Form.Get("email")
	password := c.Request.Form.Get("password")
	client_id := c.Request.Form.Get("client_id")

	if client_id == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Client ID is required"})
		return
	}
	if email == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Email is required"})
		return
	}
	if password == "" {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": "Password is required"})
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
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": err.Error()})
		return
	}

	sessionID, err := lc.sessionService.CreateSession(
		c.Request.Context(),
		user.ID.String(),
		client_id,
	)

	if err != nil {
		lc.tmpl.Execute(c.Writer, map[string]string{"Error": err.Error()})
		return
	}

	c.SetCookie(
		"session_id",
		sessionID,
		3600,
		"/",
		"localhost",
		false,
		true,
	)

	lc.tmpl.Execute(c.Writer, map[string]string{
		"Success": "User logged in successfully!",
	})
}
