package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthAccessDeniedError error

func NewOAuthAccessDeniedError(err error) OAuthAccessDeniedError {
	return OAuthAccessDeniedError(err)
}

func OAuthAccessDeniedErrorHandler(ctx context.Context, err OAuthAccessDeniedError) (int, any) {
	logrus.WithError(err).Debug("access denied error")
	return http.StatusForbidden, commonOAuthError{
		Error:            ErrAccessDenied,
		ErrorDescription: err.Error(),
	}
}
