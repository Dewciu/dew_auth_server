package oautherrors

type OAuthErrorType string

const (
	ErrInvalidRequest          OAuthErrorType = "invalid_request"
	ErrInternalServerError     OAuthErrorType = "internal_server_error"
	ErrUnauthorizedClient      OAuthErrorType = "unauthorized_client"
	ErrAccessDenied            OAuthErrorType = "access_denied"
	ErrUnsupportedResponseType OAuthErrorType = "unsupported_response_type"
	ErrInvalidScope            OAuthErrorType = "invalid_scope"
	ErrServerError             OAuthErrorType = "server_error"
	ErrInvalidClient           OAuthErrorType = "invalid_client"
	ErrInvalidGrant            OAuthErrorType = "invalid_grant"
	ErrUnsupportedGrantType    OAuthErrorType = "unsupported_grant_type"
	ErrUnsupportedTokenType    OAuthErrorType = "unsupported_token_type"
	ErrInvalidToken            OAuthErrorType = "invalid_token"
)
