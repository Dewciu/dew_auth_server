package oautherrors

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/dewciu/dew_auth_server/server/utils"
	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"
)

type OAuthInputValidationError struct {
	Err    string
	Errors interface{}
}

func (e OAuthInputValidationError) Error() string {
	return fmt.Sprintf("input validation error: %s, errors: %v", e.Err, e.Errors)
}

func NewOAuthInputValidationError(err error, input any) OAuthInputValidationError {
	if !errors.As(err, &validator.ValidationErrors{}) {
		panic("err must be of type validator.ValidationErrors")
	}

	errors := utils.ParseValidationErrors(err.(validator.ValidationErrors), input)
	return OAuthInputValidationError{
		Err:    "there are validation errors in your request",
		Errors: errors,
	}
}

func OAuthInputValidationErrorHandler(ctx context.Context, err OAuthInputValidationError) (int, any) {
	logrus.WithError(err).Debug("Input validation error")
	return http.StatusBadRequest, commonOAuthError{
		Error:            ErrInvalidRequest,
		ErrorDescription: err.Err,
		Errors:           err.Errors,
	}
}
