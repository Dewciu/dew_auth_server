package constants

// RateLimiter types
const (
	RateLimitingIpBased     = "ip"     // Rate limit based on IP address
	RateLimitingClientBased = "client" // Rate limit based on client ID
	RateLimitingUserBased   = "user"   // Rate limit based on user ID
	RateLimitingTokenBased  = "token"  // Rate limit for token endpoints
	RateLimitingGlobalBased = "global" // Global rate limiting
)
