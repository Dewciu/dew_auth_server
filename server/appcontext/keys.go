package appcontext

type AppContextKey string

const (
	ClientKey  AppContextKey = "client"
	UserIDKey  AppContextKey = "user_id"
	UserKey    AppContextKey = "user"
	SessionKey AppContextKey = "session"
)
