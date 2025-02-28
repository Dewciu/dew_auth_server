package serviceerrors

import "fmt"

type UserDoesNotExistError struct {
	email string
}

func NewUserDoesNotExistError(email string) UserDoesNotExistError {
	return UserDoesNotExistError{
		email: email,
	}
}

func (e UserDoesNotExistError) Error() string {
	return fmt.Sprintf("user with e-mail '%s' does not exist", e.email)
}

type InvalidUserPasswordError struct {
	email string
}

func NewInvalidUserPasswordError(email string) InvalidUserPasswordError {
	return InvalidUserPasswordError{
		email: email,
	}
}

func (e InvalidUserPasswordError) Error() string {
	return fmt.Sprintf("invalid password for user with e-mail '%s'", e.email)
}

type UserAlreadyExistsError struct {
	email    string
	username string
}

func NewUserAlreadyExistsError(email, username string) UserAlreadyExistsError {
	return UserAlreadyExistsError{
		email:    email,
		username: username,
	}
}

func (e UserAlreadyExistsError) Error() string {
	errStr := "user with"

	if e.email != "" {
		errStr += fmt.Sprintf(" e-mail '%s'", e.email)
	}

	if e.username != "" {
		errStr += fmt.Sprintf(" username '%s'", e.username)
	}

	return errStr + " already exists"
}
