package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthInvalidTokenError error

func NewOAuthInvalidTokenError(err error) OAuthInvalidTokenError {
	return OAuthInvalidTokenError(err)
}

func OAuthInvalidTokenErrorHandler(ctx context.Context, err OAuthInvalidTokenError) (int, any) {
	logrus.WithError(err).Debug("invalid token error")
	return http.StatusBadRequest, commonOAuthError{
		Error:            ErrInvalidToken,
		ErrorDescription: err.Error(),
	}
}
