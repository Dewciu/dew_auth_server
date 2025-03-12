package controllers

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/utils"
	"github.com/gin-gonic/gin"
)

type ClientRegisterController struct {
	tmpl          *template.Template
	clientService services.IClientService
}

func NewRegisterController(
	template *template.Template,
	clientService services.IClientService,
) ClientRegisterController {
	return ClientRegisterController{
		tmpl:          template,
		clientService: clientService,
	}
}

func (rc *ClientRegisterController) RegisterHandler(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet:
		rc.handleGet(c)
	case http.MethodPost:
		rc.handlePost(c)
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	}
}

func (rc *ClientRegisterController) handleGet(c *gin.Context) {
	rc.tmpl.Execute(c.Writer, nil)
}

func (rc *ClientRegisterController) handlePost(c *gin.Context) {
	err := c.Request.ParseForm()
	if err != nil {
		rc.tmpl.Execute(c.Writer, map[string]string{"Error": "Invalid form submission"})
		return
	}

	required_form_inputs := map[string]interface{}{
		"client_name":  c.Request.Form.Get("client_name"),
		"client_email": c.Request.Form.Get("client_email"),
		"redirect_uri": c.Request.Form.Get("redirect_uri"),
	}

	for k, v := range required_form_inputs {
		if v == "" {
			rc.tmpl.Execute(c.Writer, map[string]string{"Error": fmt.Sprintf("%s is required", k)})
			return
		}
	}

	response_types := utils.RemoveEmptyStrings([]string{
		c.Request.Form.Get("token_response_type"),
		c.Request.Form.Get("code_response_type"),
	})

	grant_types := utils.RemoveEmptyStrings([]string{
		c.Request.Form.Get("authorization_code_grant_type"),
		c.Request.Form.Get("client_credentials_grant_type"),
		c.Request.Form.Get("refresh_token_grant_type"),
		c.Request.Form.Get("password_grant_type"),
		c.Request.Form.Get("implicit_grant_type"),
	})

	scopes := utils.RemoveEmptyStrings([]string{
		c.Request.Form.Get("read_scope"),
		c.Request.Form.Get("write_scope"),
		c.Request.Form.Get("delete_scope"),
	})

	clientRegisterInput := inputs.ClientRegisterInput{
		ClientName:    required_form_inputs["client_name"].(string),
		ClientEmail:   required_form_inputs["client_email"].(string),
		RedirectURI:   required_form_inputs["redirect_uri"].(string),
		ResponseTypes: strings.Join(response_types, ","),
		GrantTypes:    strings.Join(grant_types, ","),
		Scopes:        strings.Join(scopes, ","),
	}

	output, err := rc.clientService.RegisterClient(
		c.Request.Context(),
		clientRegisterInput,
	)

	if err != nil {
		rc.tmpl.Execute(c.Writer, map[string]string{"Error": err.Error()})
		return
	}

	rc.tmpl.Execute(c.Writer, map[string]string{
		"Success":      "Client registered successfully!",
		"ClientID":     output.GetClientID(),
		"ClientSecret": output.GetClientSecret(),
	})
}
