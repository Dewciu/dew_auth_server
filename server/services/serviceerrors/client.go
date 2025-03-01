package serviceerrors

import (
	"fmt"

	"github.com/dewciu/dew_auth_server/server/constants"
)

type ClientNotFoundError struct {
	ClientID string
}

func NewClientNotFoundError(clientID string) ClientNotFoundError {
	return ClientNotFoundError{
		ClientID: clientID,
	}
}

func (e ClientNotFoundError) Error() string {
	return fmt.Sprintf("client with ID '%s' not found", e.ClientID)
}

type ClientNameConflictError struct {
	ClientName string
}

func NewClientNameConflictError(clientName string) ClientNameConflictError {
	return ClientNameConflictError{
		ClientName: clientName,
	}
}

func (e ClientNameConflictError) Error() string {
	return fmt.Sprintf("client with name '%s' already exists", e.ClientName)
}

type InvalidClientSecretError struct {
	ClientID string
}

func NewInvalidClientSecretError(clientID string) InvalidClientSecretError {
	return InvalidClientSecretError{
		ClientID: clientID,
	}
}

func (e InvalidClientSecretError) Error() string {
	return fmt.Sprintf("invalid secret for client with ID '%s'", e.ClientID)
}

type InvalidRedirectURIForClientError struct {
	ClientID string
	URI      string
}

func NewInvalidRedirectURIForClientError(clientID, uri string) InvalidRedirectURIForClientError {
	return InvalidRedirectURIForClientError{
		ClientID: clientID,
		URI:      uri,
	}
}

func (e InvalidRedirectURIForClientError) Error() string {
	return fmt.Sprintf("redirect URI '%s' is not allowed for client with ID '%s'", e.URI, e.ClientID)
}

type UnsupportedGrantTypeError struct {
	ClientID  string
	GrantType string
}

func NewUnsupportedGrantTypeError(clientID string, grantType constants.GrantType) UnsupportedGrantTypeError {
	return UnsupportedGrantTypeError{
		ClientID:  clientID,
		GrantType: string(grantType),
	}
}

func (e UnsupportedGrantTypeError) Error() string {
	return fmt.Sprintf("grant type '%s' is not supported for client with ID '%s'", e.GrantType, e.ClientID)
}

type UnsupportedResponseTypeError struct {
	ClientID     string
	ResponseType string
}

func NewUnsupportedResponseTypeError(clientID string, responseType constants.ResponseType) UnsupportedResponseTypeError {
	return UnsupportedResponseTypeError{
		ClientID:     clientID,
		ResponseType: string(responseType),
	}
}

func (e UnsupportedResponseTypeError) Error() string {
	return fmt.Sprintf("response type '%s' is not supported for client with ID '%s'", e.ResponseType, e.ClientID)
}
