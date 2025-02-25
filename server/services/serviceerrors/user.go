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
