package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthUnauthorizedClientError error

func NewOAuthUnauthorizedClientError(err error) OAuthUnauthorizedClientError {
	return OAuthUnauthorizedClientError(err)
}

func OAuthUnauthorizedClientErrorHandler(ctx context.Context, err OAuthUnauthorizedClientError) (int, any) {
	logrus.WithError(err).Debug("unauthorized client error")
	return http.StatusUnauthorized, commonOAuthError{
		Error:            ErrUnauthorizedClient,
		ErrorDescription: err.Error(),
	}
}
