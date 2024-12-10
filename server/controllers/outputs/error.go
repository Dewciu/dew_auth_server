package outputs

import (
	"github.com/dewciu/dew_auth_server/server/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

func ErrorResponse(errorType string, description string) gin.H {
	return gin.H{
		"error":             errorType,
		"error_description": description,
	}
}

func ValidationErrorResponse(errorType string, description string, ve validator.ValidationErrors, input interface{}) gin.H {
	errs := utils.ParseValidationErrors(ve, input)
	return gin.H{
		"error":             errorType,
		"error_description": description,
		"errors":            errs,
	}
}
