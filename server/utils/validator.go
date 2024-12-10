package utils

import (
	"fmt"
	"reflect"

	"github.com/go-playground/validator/v10"
)

// parseValidationErrors takes validator.ValidationErrors and converts them
// into a map of field-to-error-message for more user-friendly feedback.
func ParseValidationErrors(ve validator.ValidationErrors, input interface{}) map[string]string {
	errs := make(map[string]string)
	inputType := reflect.TypeOf(input)

	for _, fieldErr := range ve {
		var msg string
		var jsonField string

		if field, ok := inputType.FieldByName(fieldErr.Field()); ok {
			if nameTag, ok := field.Tag.Lookup("form"); ok {
				jsonField = nameTag
			}
			if nameTag, ok := field.Tag.Lookup("json"); ok {
				jsonField = nameTag
			}
		}

		switch fieldErr.ActualTag() {
		case "required":
			msg = fmt.Sprintf("%s field is required", jsonField)
		case "email":
			msg = fmt.Sprintf("%s must be a valid email address", jsonField)
		case "min":
			msg = fmt.Sprintf("%s must be at least %s characters long", jsonField, fieldErr.Param())
		case "max":
			msg = fmt.Sprintf("%s must be at most %s characters long", jsonField, fieldErr.Param())
		default:
			msg = fmt.Sprintf("%s is invalid", jsonField)
		}

		errs[jsonField] = msg
	}
	return errs
}
