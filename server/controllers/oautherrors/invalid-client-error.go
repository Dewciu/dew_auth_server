package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthInvalidClientError error

func NewOAuthInvalidClientError(err error) OAuthInvalidClientError {
	return OAuthInvalidClientError(err)
}

func OAuthInvalidClientErrorHandler(ctx context.Context, err OAuthInvalidClientError) (int, any) {
	logrus.WithError(err).Debug("invalid client error")
	return http.StatusUnauthorized, commonOAuthError{
		Error:            ErrInvalidClient,
		ErrorDescription: err.Error(),
	}
}
