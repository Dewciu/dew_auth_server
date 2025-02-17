package inputs

type IntrospectionRevocationInput struct {
	Token     string `json:"token" binding:"required"`
	TokenType string `json:"token_type" binding:"required,oneof=access_token refresh_token"`
}
