package oautherrors

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

// TODO: Split to separate files
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

type OAuthTemporarilyUnavailableError error

func NewOAuthTemporarilyUnavailableError(err error) OAuthTemporarilyUnavailableError {
	return OAuthTemporarilyUnavailableError(err)
}

func OAuthTemporarilyUnavailableErrorHandler(ctx context.Context, err OAuthTemporarilyUnavailableError) (int, any) {
	logrus.WithError(err).Debug("temporarily unavailable error")
	return http.StatusServiceUnavailable, commonOAuthError{
		Error:            ErrTemporarilyUnavailable,
		ErrorDescription: err.Error(),
	}
}

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
