package serviceerrors

import "fmt"

type ClientAuthorizationError struct {
	ClientID string
	Reason   string
}

func NewClientAuthorizationError(clientID, reason string) ClientAuthorizationError {
	return ClientAuthorizationError{
		ClientID: clientID,
		Reason:   reason,
	}
}

func (e ClientAuthorizationError) Error() string {
	return fmt.Sprintf("client with ID '%s' authorization failed: %s", e.ClientID, e.Reason)
}

type UserAuthorizationError struct {
	UserID string
	Reason string
}

func NewUserAuthorizationError(userID, reason string) UserAuthorizationError {
	return UserAuthorizationError{
		UserID: userID,
		Reason: reason,
	}
}

func (e UserAuthorizationError) Error() string {
	return fmt.Sprintf("user with ID '%s' authorization failed: %s", e.UserID, e.Reason)
}

type CodeGenerationError struct {
	Reason string
}

func NewCodeGenerationError(reason string) CodeGenerationError {
	return CodeGenerationError{
		Reason: reason,
	}
}

func (e CodeGenerationError) Error() string {
	return fmt.Sprintf("failed to generate authorization code: %s", e.Reason)
}
