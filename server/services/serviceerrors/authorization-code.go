package serviceerrors

import (
	"fmt"
)

type InvalidAuthorizationCodeError struct {
	Code string
}

func NewInvalidAuthorizationCodeError(code string) InvalidAuthorizationCodeError {
	return InvalidAuthorizationCodeError{
		Code: code,
	}
}

func (e InvalidAuthorizationCodeError) Error() string {
	return fmt.Sprintf("authorization code '%s' is invalid or expired", e.Code)
}

type InvalidRedirectURIError struct {
	ProvidedURI string
	ExpectedURI string
}

func NewInvalidRedirectURIError(providedURI, expectedURI string) InvalidRedirectURIError {
	return InvalidRedirectURIError{
		ProvidedURI: providedURI,
		ExpectedURI: expectedURI,
	}
}

func (e InvalidRedirectURIError) Error() string {
	return fmt.Sprintf("provided redirect URI '%s' does not match the expected URI '%s'", e.ProvidedURI, e.ExpectedURI)
}

type InvalidPKCEVerifierError struct {
	Reason string
}

func NewInvalidPKCEVerifierError(reason string) InvalidPKCEVerifierError {
	return InvalidPKCEVerifierError{
		Reason: reason,
	}
}

func (e InvalidPKCEVerifierError) Error() string {
	return fmt.Sprintf("PKCE verification failed: %s", e.Reason)
}

type UnsupportedPKCEMethodError struct {
	Method string
}

func NewUnsupportedPKCEMethodError(method string) UnsupportedPKCEMethodError {
	return UnsupportedPKCEMethodError{
		Method: method,
	}
}

func (e UnsupportedPKCEMethodError) Error() string {
	return fmt.Sprintf("unsupported PKCE code challenge method: %s", e.Method)
}
