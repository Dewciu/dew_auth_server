package servicecontexts

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
)

type AuthorizationContext struct {
	context.Context
	Client *models.Client
	UserID string
}

func NewAuthContext(ctx context.Context) AuthorizationContext {
	return AuthorizationContext{
		Context: ctx,
	}
}
