package handlers

import "context"

type AuthContext struct {
	context.Context
	SessionID string
	UserID    string
}

func NewAuthContext(ctx context.Context) AuthContext {
	return AuthContext{
		Context: ctx,
	}
}
