package constants

type GrantTypeError string

const (
	InvalidGrantError    GrantTypeError = "invalid_grant"
	UnsupportedGrantType GrantTypeError = "unsupported_grant_type"
)
