package appcontext

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
)

func WithUser(ctx context.Context, user *models.User) context.Context {
	ctx = context.WithValue(ctx, UserIDKey, user.ID.String())
	return context.WithValue(ctx, UserKey, user)
}

func GetUser(ctx context.Context) (*models.User, bool) {
	user, ok := ctx.Value(UserKey).(*models.User)
	return user, ok
}

func MustGetUser(ctx context.Context) *models.User {
	user, ok := GetUser(ctx)
	if !ok {
		panic("user not found in context")
	}
	return user
}

func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

func GetUserID(ctx context.Context) (string, bool) {
	if userID, ok := ctx.Value(UserIDKey).(string); ok {
		return userID, true
	}

	if user, ok := GetUser(ctx); ok {
		return user.ID.String(), true
	}

	return "", false
}

func MustGetUserID(ctx context.Context) string {
	userID, ok := GetUserID(ctx)
	if !ok {
		panic("user ID not found in context")
	}
	return userID
}
