package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type OAuthUnsupportedTokenTypeError error

func NewOAuthUnsupportedTokenTypeError(err error) OAuthUnsupportedTokenTypeError {
	return OAuthUnsupportedTokenTypeError(err)
}

func OAuthUnsupportedTokenTypeErrorHandler(ctx context.Context, err OAuthUnsupportedTokenTypeError) (int, any) {
	logrus.WithError(err).Debug("unsupported token type error")
	return http.StatusBadRequest, commonOAuthError{
		Error:            ErrUnsupportedTokenType,
		ErrorDescription: err.Error(),
	}
}
