package appcontext

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
)

func WithClient(ctx context.Context, client *models.Client) context.Context {
	return context.WithValue(ctx, ClientKey, client)
}

func GetClient(ctx context.Context) (*models.Client, bool) {
	client, ok := ctx.Value(ClientKey).(*models.Client)
	return client, ok
}

func MustGetClient(ctx context.Context) *models.Client {
	client, ok := GetClient(ctx)
	if !ok {
		panic("client not found in context")
	}
	return client
}
