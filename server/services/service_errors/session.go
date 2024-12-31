package service_errors

type NoUserInSessionError struct {
	sessionID string
}

func NewNoUserInSessionError(sessionID string) *NoUserInSessionError {
	return &NoUserInSessionError{}
}

func (e *NoUserInSessionError) Error() string {
	return "no user in session with id " + e.sessionID
}
