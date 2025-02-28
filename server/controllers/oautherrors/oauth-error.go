package oautherrors

type commonOAuthError struct {
	Error            OAuthErrorType `json:"error"`
	ErrorDescription string         `json:"error_description"`
	Errors           interface{}    `json:"errors,omitempty"`
}
