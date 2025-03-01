package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthInvalidScopeError error

func NewOAuthInvalidScopeError(err error) OAuthInvalidScopeError {
	return OAuthInvalidScopeError(err)
}

func OAuthInvalidScopeErrorHandler(ctx context.Context, err OAuthInvalidScopeError) (int, any) {
	logrus.WithError(err).Debug("invalid scope error")
	return http.StatusBadRequest, commonOAuthError{
		Error:            ErrInvalidScope,
		ErrorDescription: err.Error(),
	}
}
