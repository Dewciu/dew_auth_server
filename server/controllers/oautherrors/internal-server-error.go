package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthInternalServerError error

func NewOAuthInternalServerError(err error) OAuthInternalServerError {
	return OAuthInternalServerError(err)
}

func OAuthInternalServerErrorHandler(ctx context.Context, err OAuthInternalServerError) (int, any) {
	logrus.WithError(err).Error("Internal server error")
	return http.StatusInternalServerError, commonOAuthError{
		Error:            ErrInternalServerError,
		ErrorDescription: "Something went wrong...",
	}
}
