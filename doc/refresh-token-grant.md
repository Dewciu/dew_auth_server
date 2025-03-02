# Refresh Token Grant

## Overview

The Refresh Token grant type allows clients to obtain a new access token when the current one expires, without requiring the user to re-authenticate. This improves the user experience while maintaining security through short-lived access tokens.

This grant type is implemented in the Dew Auth Server following [RFC 6749 Section 6](https://tools.ietf.org/html/rfc6749#section-6).

## When to Use

The Refresh Token grant is used when:

1. An access token has expired or is about to expire
2. Long-term API access is needed without requiring the user to re-authenticate
3. You want to implement secure token rotation practices

## Flow Diagram

```
+--------+                                           +---------------+
|        |--(A)------- Authorization Grant --------->|               |
|        |                                           |               |
|        |<-(B)----------- Access Token -------------|               |
|        |               & Refresh Token             |               |
|        |                                           |               |
|        |                            +----------+   |               |
|        |--(C)---- Access Token ---->|          |   |               |
|        |                            |          |   |               |
|        |<-(D)- Protected Resource --| Resource |   | Authorization |
| Client |                            |  Server  |   |     Server    |
|        |--(E)---- Access Token ---->|          |   |               |
|        |                            |          |   |               |
|        |<-(F)- Invalid Token Error -|          |   |               |
|        |                            +----------+   |               |
|        |                                           |               |
|        |--(G)----------- Refresh Token ----------->|               |
|        |                                           |               |
|        |<-(H)----------- Access Token -------------|               |
+--------+           & Optional Refresh Token        +---------------+
```

## Using the Refresh Token Grant

### 1. Obtaining a Refresh Token

Refresh tokens are initially issued alongside access tokens when using grant types like Authorization Code or Resource Owner Password Credentials.

### 2. Token Refresh Request

When the access token expires, the client requests a new one by sending the refresh token:

```
POST /oauth2/token HTTP/1.1
Host: dew-auth-server.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&scope=read
```

**Required Parameters:**

- `grant_type`: Must be "refresh_token"
- `refresh_token`: The refresh token previously issued
- Client authentication via the Authorization header using Basic auth (recommended) or via the request body using `client_id` and `client_secret` parameters

**Optional Parameters:**

- `scope`: The requested scope(s) for the new access token. This must be equal to or a subset of the original scope. If omitted, the server will use the same scope as the original access token.

### 3. Token Refresh Response

If the refresh request is valid, the server responds with a new access token and optionally a new refresh token:

```json
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8", 
  "scope": "read"
}
```

Note that the response may contain a new refresh token. If it does, the client should discard the old refresh token and use the new one for future refreshes.

If the refresh request fails, the server responds with an error:

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "error": "invalid_grant",
  "error_description": "The refresh token is invalid or has expired"
}
```

## Security Considerations

### Token Rotation

Token rotation is a security practice where a new refresh token is issued each time an access token is refreshed. The Dew Auth Server implementation supports token rotation by:

1. Issuing a new refresh token in the refresh response
2. Invalidating the old refresh token once it has been used

This protects against replay attacks and refresh token theft.

### Refresh Token Expiration

Refresh tokens should have longer lifetimes than access tokens but should still expire eventually to limit the potential damage from a leaked token. The Dew Auth Server allows configurable expiration times for refresh tokens.

### Scope Reduction

Clients can request a reduced scope when refreshing tokens, but cannot escalate privileges by requesting additional scopes not included in the original authorization.

## Client Registration Requirements

For a client to use the refresh token grant type, it must:

1. Be registered with the Dew Auth Server
2. Have "refresh_token" included in its permitted grant types
3. Have proper secure storage for refresh tokens
4. Implement proper token management (handling rotation, expiration, etc.)

## Sample Code

### cURL Example

```bash
curl -X POST \
  https://dew-auth-server.com/oauth2/token \
  -H 'Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA'
```

### JavaScript Example

```javascript
async function refreshAccessToken(refreshToken) {
  const tokenEndpoint = 'https://dew-auth-server.com/oauth2/token';
  const clientId = 'your-client-id';
  const clientSecret = 'your-client-secret';
  
  const formData = new URLSearchParams();
  formData.append('grant_type', 'refresh_token');
  formData.append('refresh_token', refreshToken);
  
  try {
    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa(`${clientId}:${clientSecret}`)
      },
      body: formData
    });
    
    if (!response.ok) {
      throw new Error('Token refresh failed');
    }
    
    const data = await response.json();
    
    // Save the new tokens
    localStorage.setItem('access_token', data.access_token);
    
    // If a new refresh token is returned, save it
    if (data.refresh_token) {
      localStorage.setItem('refresh_token', data.refresh_token);
    }
    
    return data.access_token;
  } catch (error) {
    console.error('Error refreshing token:', error);
    // Handle authentication errors (e.g., redirect to login)
    throw error;
  }
}

// Example usage in an API request function
async function fetchProtectedResource(url) {
  let accessToken = localStorage.getItem('access_token');
  
  try {
    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });
    
    // If token is expired
    if (response.status === 401) {
      // Attempt to refresh the token
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }
      
      accessToken = await refreshAccessToken(refreshToken);
      
      // Retry the request with the new token
      return fetch(url, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
    }
    
    return response;
  } catch (error) {
    console.error('API request failed:', error);
    throw error;
  }
}
```

## Best Practices

1. **Secure Storage**: Store refresh tokens securely, preferably using secure storage mechanisms provided by the platform.

2. **Token Management**: 
   - Keep track of issued refresh tokens
   - Handle token rotation properly (discard old tokens when new ones are issued)
   - Implement proper error handling for token refresh failures

3. **Automatic Refresh**: Implement automatic token refresh when access tokens expire, typically by:
   - Proactively refreshing tokens before they expire
   - Refreshing upon receiving a 401 Unauthorized response
   - Using an interceptor or middleware pattern to handle token refreshes transparently

4. **Refresh Token Cleanup**: Implement mechanisms to clean up or revoke unused refresh tokens.

5. **Monitoring**: Monitor refresh token usage for suspicious patterns that might indicate compromise.

6. **Stateful Handling**: Consider implementing a stateful approach where the server keeps track of issued refresh tokens and their status.

This implementation of the Refresh Token grant follows the OAuth 2.0 specification while adding security enhancements like token rotation and reuse detection to provide a more secure experience.