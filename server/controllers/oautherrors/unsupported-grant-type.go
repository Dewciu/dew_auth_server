package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthUnsupportedGrantTypeError error

func NewOAuthUnsupportedGrantTypeError(err error) OAuthUnsupportedGrantTypeError {
	return OAuthUnsupportedGrantTypeError(err)
}

func OAuthUnsupportedGrantTypeErrorHandler(ctx context.Context, err OAuthUnsupportedGrantTypeError) (int, any) {
	logrus.WithError(err).Debug("unsupported grant type error")
	return http.StatusBadRequest, commonOAuthError{
		Error:            ErrUnsupportedGrantType,
		ErrorDescription: err.Error(),
	}
}
