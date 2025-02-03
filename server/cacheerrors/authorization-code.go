package cacheerrors

type MissingAuthorizationCodeError struct{}

func (e *MissingAuthorizationCodeError) Error() string {
	return "missing authorization code: the authorization code is required but was not provided"
}

type MissingUserIDError struct{}

func (e *MissingUserIDError) Error() string {
	return "missing user ID: the user ID is required but was not provided"
}

type MissingRedirectURIError struct{}

func (e *MissingRedirectURIError) Error() string {
	return "missing redirect URI: the redirect URI is required but was not provided"
}

type MissingCodeChallengeError struct{}

func (e *MissingCodeChallengeError) Error() string {
	return "missing code challenge: the code challenge is required but was not provided"
}

type MissingCodeChallengeMethodError struct{}

func (e *MissingCodeChallengeMethodError) Error() string {
	return "missing code challenge method: the code challenge method is required but was not provided"
}
