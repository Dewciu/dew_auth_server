package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthTooManyRequestsError error

func NewOAuthTooManyRequestsError(err error) OAuthTooManyRequestsError {
	return OAuthTooManyRequestsError(err)
}

func OAuthTooManyRequestsErrorHandler(ctx context.Context, err OAuthTooManyRequestsError) (int, any) {
	logrus.WithError(err).Debug("too many requests error")
	return http.StatusTooManyRequests, commonOAuthError{
		Error:            ErrTooManyRequests,
		ErrorDescription: err.Error(),
	}
}
