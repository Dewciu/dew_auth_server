package serviceerrors

import "fmt"

type ConsentNotFoundError struct {
	UserID   string
	ClientID string
}

func NewConsentNotFoundError(userID, clientID string) ConsentNotFoundError {
	return ConsentNotFoundError{
		UserID:   userID,
		ClientID: clientID,
	}
}

func (e ConsentNotFoundError) Error() string {
	return fmt.Sprintf("consent not found for user '%s' and client '%s'", e.UserID, e.ClientID)
}

type ConsentDeniedError struct {
	UserID   string
	ClientID string
}

func NewConsentDeniedError(userID, clientID string) ConsentDeniedError {
	return ConsentDeniedError{
		UserID:   userID,
		ClientID: clientID,
	}
}

func (e ConsentDeniedError) Error() string {
	return fmt.Sprintf("consent denied by user '%s' for client '%s'", e.UserID, e.ClientID)
}

type InvalidScopeError struct {
	RequestedScope string
	AllowedScopes  string
}

func NewInvalidScopeError(requestedScope, allowedScopes string) InvalidScopeError {
	return InvalidScopeError{
		RequestedScope: requestedScope,
		AllowedScopes:  allowedScopes,
	}
}

func (e InvalidScopeError) Error() string {
	return fmt.Sprintf("requested scope '%s' is not allowed; allowed scopes are: '%s'", e.RequestedScope, e.AllowedScopes)
}
