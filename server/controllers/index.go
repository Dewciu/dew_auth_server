package controllers

import (
	"fmt"
	"html/template"

	"github.com/gin-gonic/gin"
)

type IndexController struct {
	tmpl *template.Template
}

func NewIndexController(templatePath string) IndexController {
	return IndexController{
		tmpl: template.Must(template.ParseFiles(templatePath + "/index.html")),
	}
}

func (ic *IndexController) IndexHandler(c *gin.Context) {
	ic.tmpl.Execute(c.Writer, nil)
	fmt.Println("Index page")
}
