package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthInvalidGrantError error

func NewOAuthInvalidGrantError(err error) OAuthInvalidGrantError {
	return OAuthInvalidGrantError(err)
}

func OAuthInvalidGrantErrorHandler(ctx context.Context, err OAuthInvalidGrantError) (int, any) {
	logrus.WithError(err).Debug("invalid grant error")
	return http.StatusBadRequest, commonOAuthError{
		Error:            ErrInvalidGrant,
		ErrorDescription: err.Error(),
	}
}
