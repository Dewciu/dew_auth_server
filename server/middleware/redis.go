package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func AddRedisClientToContext(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("rdc", redisClient)
		c.Next()
	}
}
