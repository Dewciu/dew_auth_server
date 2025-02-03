package cacheerrors

type MissingTokenError struct{}

func (e *MissingTokenError) Error() string {
	return "missing access token: the access token is required but was not provided"
}

type MissingTokenTypeError struct{}

func (e *MissingTokenTypeError) Error() string {
	return "missing token type: the token type is required but was not provided"
}

type MissingExpiresInError struct{}

func (e *MissingExpiresInError) Error() string {
	return "missing expires in: the expiration time is required but was not provided"
}
