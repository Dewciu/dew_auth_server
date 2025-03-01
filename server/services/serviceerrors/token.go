package serviceerrors

import "fmt"

type TokenGenerationError struct {
	Reason string
}

func NewTokenGenerationError(reason string) TokenGenerationError {
	return TokenGenerationError{
		Reason: reason,
	}
}

func (e TokenGenerationError) Error() string {
	return fmt.Sprintf("failed to generate token: %s", e.Reason)
}

type InvalidTokenError struct {
	Token  string
	Reason string
}

func NewInvalidTokenError(token, reason string) InvalidTokenError {
	return InvalidTokenError{
		Token:  token,
		Reason: reason,
	}
}

func (e InvalidTokenError) Error() string {
	// Don't include the full token in error messages for security reasons
	tokenPreview := ""
	if len(e.Token) > 8 {
		tokenPreview = e.Token[:4] + "..." + e.Token[len(e.Token)-4:]
	} else if len(e.Token) > 0 {
		tokenPreview = e.Token[:1] + "..."
	}

	return fmt.Sprintf("invalid token %s: %s", tokenPreview, e.Reason)
}

type TokenExpiredError struct {
	TokenType string
}

func NewTokenExpiredError(tokenType string) TokenExpiredError {
	return TokenExpiredError{
		TokenType: tokenType,
	}
}

func (e TokenExpiredError) Error() string {
	return fmt.Sprintf("%s token has expired", e.TokenType)
}

type TokenRevokedError struct {
	TokenType string
}

func NewTokenRevokedError(tokenType string) TokenRevokedError {
	return TokenRevokedError{
		TokenType: tokenType,
	}
}

func (e TokenRevokedError) Error() string {
	return fmt.Sprintf("%s token has been revoked", e.TokenType)
}

type TokenClientMismatchError struct {
	ExpectedClientID string
	ActualClientID   string
}

func NewTokenClientMismatchError(expectedClientID, actualClientID string) TokenClientMismatchError {
	return TokenClientMismatchError{
		ExpectedClientID: expectedClientID,
		ActualClientID:   actualClientID,
	}
}

func (e TokenClientMismatchError) Error() string {
	return fmt.Sprintf("token was issued to client '%s' but is being used by client '%s'", e.ActualClientID, e.ExpectedClientID)
}

type MultipleTokensFoundError struct {
	UserID   string
	ClientID string
}

func NewMultipleTokensFoundError(userID, clientID string) MultipleTokensFoundError {
	return MultipleTokensFoundError{
		UserID:   userID,
		ClientID: clientID,
	}
}

func (e MultipleTokensFoundError) Error() string {
	return fmt.Sprintf("multiple active tokens found for user '%s' and client '%s'", e.UserID, e.ClientID)
}

type TokenNotFoundError struct {
	Token string
}

func NewTokenNotFoundError(token string) TokenNotFoundError {
	return TokenNotFoundError{
		Token: token,
	}
}

func (e TokenNotFoundError) Error() string {
	return fmt.Sprintf("token '%s' not found", e.Token)
}
