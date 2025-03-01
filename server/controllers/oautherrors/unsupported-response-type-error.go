package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthUnsupportedResponseTypeError error

func NewOAuthUnsupportedResponseTypeError(err error) OAuthUnsupportedResponseTypeError {
	return OAuthUnsupportedResponseTypeError(err)
}

func OAuthUnsupportedResponseTypeErrorHandler(ctx context.Context, err OAuthUnsupportedResponseTypeError) (int, any) {
	logrus.WithError(err).Debug("unsupported response type error")
	return http.StatusBadRequest, commonOAuthError{
		Error:            ErrUnsupportedResponseType,
		ErrorDescription: err.Error(),
	}
}
