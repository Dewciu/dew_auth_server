# Client Credentials Grant

## Overview

The Client Credentials grant type allows clients to obtain an access token by authenticating with their own credentials, without involving a resource owner (user). This flow is appropriate when the client is acting on its own behalf (client-as-resource-owner) rather than on behalf of a user.

This grant type is implemented in the Dew Auth Server following [RFC 6749 Section 4.4](https://tools.ietf.org/html/rfc6749#section-4.4).

## When to Use

The Client Credentials grant is suitable for:

1. Machine-to-machine (M2M) authentication
2. Backend services accessing APIs without user involvement
3. Clients accessing resources they own or have been pre-authorized to access
4. Daemon processes and background jobs

## Flow Diagram

```
      +--------+                               +---------------+
      |        |--(A)- Client Authentication -->|               |
      | Client |                               | Authorization |
      |        |<-(B)---- Access Token --------|    Server     |
      +--------+                               +---------------+
```

## Using the Client Credentials Grant

### 1. Token Request

The client authenticates with the authorization server and requests an access token:

```
POST /oauth2/token HTTP/1.1
Host: dew-auth-server.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=read+write
```

**Required Parameters:**

- `grant_type`: Must be "client_credentials"
- Client authentication via the Authorization header using Basic auth (recommended) or via the request body using `client_id` and `client_secret` parameters

**Optional Parameters:**

- `scope`: The requested scope(s) of the access token. If omitted, the server will use the client's default registered scopes.

### 2. Token Response

If the authentication is successful, the server responds with an access token:

```json
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

Note that unlike other grant types, the Client Credentials grant does not return a refresh token, as specified in RFC 6749.

If the authentication fails, the server responds with an error:

```json
HTTP/1.1 401 Unauthorized
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

## Client Registration Requirements

For a client to use the client credentials grant type, it must:

1. Be registered with the Dew Auth Server as a confidential client
2. Have secure storage for its client secret
3. Have "client_credentials" included in its permitted grant types
4. Be configured with appropriate scope permissions

## Security Considerations

1. **Confidential Clients Only**: This grant type should only be used by confidential clients that can securely store their credentials.
2. **TLS Required**: Always use HTTPS to protect client credentials in transit.
3. **Strong Secrets**: Use strong client secrets to prevent brute force attacks.
4. **Limited Scopes**: Only grant the minimum necessary scopes to the client.
5. **Short-lived Tokens**: Access tokens should have limited lifetimes.
6. **Rate Limiting**: Implement rate limiting to prevent credential stuffing attacks.

## Sample Code

### cURL Example

```bash
curl -X POST \
  https://dew-auth-server.com/oauth2/token \
  -H 'Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&scope=read%20write'
```

### Node.js Example

```javascript
const axios = require('axios');

async function getClientCredentialsToken() {
  const clientId = 'your-client-id';
  const clientSecret = 'your-client-secret';
  
  try {
    const response = await axios({
      method: 'post',
      url: 'https://dew-auth-server.com/oauth2/token',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
      },
      data: 'grant_type=client_credentials&scope=read%20write'
    });
    
    return response.data;
  } catch (error) {
    console.error('Error getting token:', error.response ? error.response.data : error.message);
    throw error;
  }
}

// Usage
getClientCredentialsToken()
  .then(tokenData => {
    console.log('Access token:', tokenData.access_token);
    
    // Use the token to make API requests
    return axios.get('https://api.example.com/resources', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`
      }
    });
  })
  .then(apiResponse => {
    console.log('API response:', apiResponse.data);
  })
  .catch(error => {
    console.error('Error:', error);
  });
```

### Go Example

```go
package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func getClientCredentialsToken() (string, error) {
	clientID := "your-client-id"
	clientSecret := "your-client-secret"
	
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "read write")
	
	req, err := http.NewRequest("POST", "https://dew-auth-server.com/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Add basic auth
	auth := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	req.Header.Set("Authorization", "Basic "+auth)
	
	// Make request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	// Read response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error response: %s", string(body))
	}
	
	return string(body), nil
}

func main() {
	token, err := getClientCredentialsToken()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	fmt.Printf("Token response: %s\n", token)
	
	// Use token for API requests...
}
```

## Best Practices

1. **Separate Client Credentials**: Use different client credentials for different applications or environments.
2. **Audit Trail**: Maintain logs of client credential usage for security monitoring.
3. **Credential Rotation**: Implement a process for regular rotation of client secrets.
4. **Scope Limitation**: Always request the minimal scope necessary for the operation.
5. **Token Caching**: Cache tokens until they expire to reduce the number of token requests.
6. **Error Handling**: Implement proper error handling and retries for token acquisition failures.

Remember that the Client Credentials grant is designed for machine-to-machine communication where the client is acting on its own behalf, not on behalf of a user.