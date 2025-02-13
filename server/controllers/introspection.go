package controllers

import (
	"github.com/gin-gonic/gin"
)

type IntrospectionController struct {
}

func NewIntrospectionController() IntrospectionController {
	return IntrospectionController{}
}

func (i *IntrospectionController) Introspect(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Introspection",
	})
}
