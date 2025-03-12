package controllers

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/gin-gonic/gin"
)

type UserRegisterController struct {
	tmpl        *template.Template
	userService services.IUserService
}

func NewUserRegisterController(
	template *template.Template,
	userService services.IUserService,
) UserRegisterController {
	return UserRegisterController{
		tmpl:        template,
		userService: userService,
	}
}

func (rc *UserRegisterController) RegisterHandler(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet:
		rc.handleGet(c)
	case http.MethodPost:
		rc.handlePost(c)
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	}
}

func (rc *UserRegisterController) handleGet(c *gin.Context) {
	rc.tmpl.Execute(c.Writer, nil)
}

func (rc *UserRegisterController) handlePost(c *gin.Context) {
	err := c.Request.ParseForm()
	if err != nil {
		rc.tmpl.Execute(c.Writer, map[string]string{"Error": "Invalid form submission"})
		return
	}

	required_form_inputs := map[string]interface{}{
		"username": c.Request.Form.Get("username"),
		"email":    c.Request.Form.Get("email"),
		"password": c.Request.Form.Get("password"),
	}

	for k, v := range required_form_inputs {
		if v == "" {
			rc.tmpl.Execute(c.Writer, map[string]string{"Error": fmt.Sprintf("%s is required", k)})
			return
		}
	}

	userRegisterInput := inputs.UserRegisterInput{
		Username: required_form_inputs["username"].(string),
		Email:    required_form_inputs["email"].(string),
		Password: required_form_inputs["password"].(string),
	}

	err = rc.userService.RegisterUser(
		c.Request.Context(),
		&userRegisterInput,
	)

	if err != nil {
		if _, ok := err.(serviceerrors.UserAlreadyExistsError); ok {
			rc.tmpl.Execute(c.Writer, map[string]string{"Error": "User already exists"})
			return
		}

		rc.tmpl.Execute(c.Writer, map[string]string{"Error": "An error occurred while registering the user"})
		return
	}

	rc.tmpl.Execute(c.Writer, map[string]string{
		"Success": "User registered successfully!",
	})
}
