package appcontext

import (
	"context"

	"github.com/gin-contrib/sessions"
)

func WithSession(ctx context.Context, session sessions.Session) context.Context {
	ctx = context.WithValue(ctx, SessionKey, session)
	return context.WithValue(ctx, SessionKey, session)
}

func GetSession(ctx context.Context) (sessions.Session, bool) {
	session, ok := ctx.Value(SessionKey).(sessions.Session)
	return session, ok
}

func MustGetSession(ctx context.Context) sessions.Session {
	session, ok := GetSession(ctx)
	if !ok {
		panic("session not found in context")
	}
	return session
}
