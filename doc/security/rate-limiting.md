# Rate Limiting in Dew Auth Server

## Overview

Rate limiting is a security feature that limits the number of requests a client can make to the server within a specified time window. This helps protect the server from abuse, denial-of-service attacks, and brute force attempts.

The Dew Auth Server implements rate limiting for critical OAuth endpoints, with different limits based on the endpoint type and sensitivity. This document describes how rate limiting works, how to configure it, and how to troubleshoot rate limiting issues.

## Rate Limiting Strategies

The rate limiting feature implements multiple strategies:

1. **IP-based Limiting**: Restricts requests based on the client's IP address.
2. **Client-based Limiting**: Restricts requests based on the OAuth client ID.
3. **User-based Limiting**: Restricts requests based on the authenticated user ID.
4. **Token-based Limiting**: Specialized limiting for token endpoints.
5. **Global Limiting**: Limits requests across the entire server.

## Default Configuration

The server applies different rate limits to different endpoint types:

| Endpoint Type | Default Limit | Window | Strategy | Purpose |
|---------------|--------------|--------|----------|---------|
| Token Endpoints | 60 requests | 60 seconds | Token-based | Prevent token harvesting |
| Auth Endpoints | 100 requests | 60 seconds | IP-based | Allow normal usage while preventing scanning |
| User Endpoints | 5 requests | 60 seconds | IP-based | Prevent brute force attacks |
| Common Endpoints | 75 requests | 60 seconds | IP-based | DDoS Protection |

## Configuration

Rate limiting can be configured using environment variables:

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `RATE_LIMITING_ENABLED` | Enable or disable rate limiting | `false` |
| `RATE_LIMIT_TOKEN` | Maximum requests for token endpoints | `60` |
| `RATE_LIMIT_AUTH` | Maximum requests for authorization endpoints | `100` |
| `RATE_LIMIT_LOGIN` | Maximum requests for login endpoints | `5` |
| `RATE_LIMIT_COMMON` | Maximum requests for login endpoints | `10` |
| `RATE_LIMIT_WINDOW_SECS` | Time window in seconds | `60` |
| `RATE_LIMIT_EXEMPTED_IPS` | Comma-separated list of IPs to exempt | `` |

### Example Configuration

Add these settings to your `.env` file:

```
RATE_LIMITING_ENABLED=true
RATE_LIMIT_TOKEN=60
RATE_LIMIT_AUTH=100
RATE_LIMIT_LOGIN=5
RATE_LIMIT_WINDOW_SECS=60
RATE_LIMIT_EXEMPTED_IPS=127.0.0.1,192.168.1.100
```

## Storage Backends

The rate limiter supports one storage backend:

1. **Redis Store** (recommended for production): Provides distributed rate limiting across multiple server instances.

## Client Response

When a client exceeds the rate limit, the server responds with:

- HTTP status code `429 Too Many Requests`
- JSON error response with details:
  ```json
  {
    "error": "server_error",
    "error_description": "Rate limit exceeded. Please try again later."
  }
  ```
- `Retry-After` header with the number of seconds to wait before retrying

Clients can also monitor their remaining quota using these response headers:

- `X-RateLimit-Limit`: Maximum number of requests allowed in the window
- `X-RateLimit-Remaining`: Number of requests remaining in the current window

## Exemptions

Specific IPs can be exempted from rate limiting using the `RATE_LIMIT_EXEMPTED_IPS` environment variable. This is useful for:

- Internal services
- Load balancers
- Monitoring tools
- Development environments

## Security Considerations

1. **Choose Appropriate Limits**: Set limits that allow legitimate use but prevent abuse.

2. **Protect Login Endpoints**: Keep strict limits on login attempts to prevent brute force attacks.

3. **Distributed Deployments**: Use Redis as the storage backend in distributed environments.

4. **IP Spoofing**: Be aware that determined attackers might attempt to bypass IP-based rate limiting using spoofed IPs or proxies.

## Troubleshooting

### Common Issues

1. **False Positives**: If legitimate users are being rate limited, consider:
   - Increasing the limits for specific endpoints
   - Exempting known good IPs
   - Implementing more sophisticated rate limiting based on client behavior

2. **Load Balancer Configuration**: Ensure your load balancer correctly forwards client IP addresses using the X-Forwarded-For header.

### Monitoring Rate Limiting

When rate limiting is active, the server logs rate limiting events:

- When a client exceeds a rate limit
- When a rate limiter store experiences errors
- When a rate limit key can't be generated

Monitor these logs to detect potential attacks or misconfiguration.

## Example: Client Implementation

Here's an example of how a client might handle rate limiting responses:

```javascript
async function makeAuthRequest(endpoint, data) {
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      body: JSON.stringify(data),
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After') || 60;
      console.log(`Rate limited. Retry after ${retryAfter} seconds`);
      // Implement exponential backoff or retry logic
      return new Promise((resolve) => {
        setTimeout(() => resolve(makeAuthRequest(endpoint, data)), retryAfter * 1000);
      });
    }
    
    return response.json();
  } catch (error) {
    console.error('Request failed:', error);
    throw error;
  }
}
```