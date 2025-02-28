package serviceerrors

type NoUserInSessionError struct {
	sessionID string
}

func NewNoUserInSessionError(sessionID string) *NoUserInSessionError {
	return &NoUserInSessionError{
		sessionID: sessionID,
	}
}

func (e *NoUserInSessionError) Error() string {
	return "no user in session with id " + e.sessionID
}
