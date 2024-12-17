package controllers

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type RegisterController struct {
	tmpl *template.Template
}

func NewRegisterController() RegisterController {
	return RegisterController{
		tmpl: template.Must(template.ParseFiles("server/controllers/templates/register-client.html")),
	}
}

func (rc *RegisterController) RegisterHandler(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet:
		rc.handleGet(c)
	case http.MethodPost:
		rc.handlePost(c)
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	}
}

func (rc *RegisterController) handleGet(c *gin.Context) {
	rc.tmpl.Execute(c.Writer, nil)
}

func (rc *RegisterController) handlePost(c *gin.Context) {
	err := c.Request.ParseForm()
	if err != nil {
		rc.tmpl.Execute(c.Writer, map[string]string{"Error": "Invalid form submission"})
		return
	}

	clientName := strings.TrimSpace(c.Request.Form.Get("client_name"))
	clientEmail := strings.TrimSpace(c.Request.Form.Get("client_email"))
	clientSecret := strings.TrimSpace(c.Request.Form.Get("client_secret"))

	// Simple validation
	if clientName == "" || clientEmail == "" || clientSecret == "" {
		rc.tmpl.Execute(c.Writer, map[string]string{"Error": "All fields are required"})
		return
	}

	// Example: Store the client info in the database/repository (Not implemented here)
	// repository.CreateClient(clientName, clientEmail, clientSecret)

	rc.tmpl.Execute(c.Writer, map[string]string{"Success": "Client registered successfully!"})
}
