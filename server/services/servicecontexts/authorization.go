package servicecontexts

import "context"

type AuthorizationContext struct {
	context.Context
	SessionID string
	UserID    string
}

func NewAuthContext(ctx context.Context) AuthorizationContext {
	return AuthorizationContext{
		Context: ctx,
	}
}
