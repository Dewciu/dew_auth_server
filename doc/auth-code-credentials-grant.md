# Authorization Code Grant

## Overview

The Authorization Code grant type is a secure, server-side flow that allows clients to obtain access tokens by first receiving an authorization code. This grant type is particularly suitable for confidential clients and web applications, providing enhanced security through the separation of authorization and token issuance.

This implementation follows the OAuth 2.0 specification ([RFC 6749 Section 4.1](https://tools.ietf.org/html/rfc6749#section-4.1)) and incorporates Proof Key for Code Exchange (PKCE) for additional security.

## When to Use

The Authorization Code grant is ideal for:

1. Web applications with server-side rendering
2. Native mobile and desktop applications
3. Single-page applications (SPAs) with backend support
4. Scenarios requiring enhanced security and token separation

## Key Features

- Secure two-step token acquisition process
- PKCE (Proof Key for Code Exchange) support
- Prevents token interception
- Supports long-lived refresh tokens
- Enables granular scope control

## Flow Diagram

```
+----------+
| Resource |
| Owner    |
| (User)   |
+----------+
    ^
    |
(B) Authorization Grant
    |
+----|-----+ Client Identifier +---------------+
| User-    | & Redirection URI | Authorization |
| Agent    |-----------------→|   Server      |
|          |<----------------|               |
|          | (C) Authorization Code           |
+-|---------+               +---------------+
  |
  | (D) Authorization Code &
  |      Redirection URI
  ↓
+---------+
| Client  |
|         |
+---------+
    |
    | (E) Access Token Request
    ↓
+---------------+
| Authorization |
|    Server     |
+---------------+
    |
    | (F) Access Token Response
    ↓
+---------+
| Client  |
|         |
+---------+
```

## Authorization Request

### Step 1: Initial Authorization Request

The client redirects the user to the authorization server with the following parameters:

```
GET /oauth2/authorize?
  response_type=code&
  client_id=s6BhdRkqt3&
  state=xyz&
  redirect_uri=https://client.example.com/cb&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

**Required Parameters:**
- `response_type`: Must be `code`
- `client_id`: The client's registered identifier
- `redirect_uri`: Registered client callback URL
- `code_challenge`: PKCE code challenge
- `code_challenge_method`: PKCE method (`S256` or `plain`)
- `state`: CSRF protection token

**Optional Parameters:**
- `scope`: Requested access scopes

### Step 2: User Authentication and Consent

The user authenticates and decides whether to grant or deny the client's access request.

### Step 3: Authorization Code Issuance

Upon approval, the authorization server redirects the user back to the client:

```
HTTP/1.1 302 Found
Location: https://client.example.com/cb?
  code=SplxlOBeZQQYbYS6WxSbIA&
  state=xyz
```

## Token Request

### Step 4: Token Exchange

The client exchanges the authorization code for an access token:

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=SplxlOBeZQQYbYS6WxSbIA&
redirect_uri=https://client.example.com/cb&
client_id=s6BhdRkqt3&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Required Parameters:**
- `grant_type`: Must be `authorization_code`
- `code`: Authorization code received in step 3
- `redirect_uri`: Must match the initial request's URI
- `client_id`: The client's identifier
- `code_verifier`: PKCE code verifier

### Token Response

```json
{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "scope": "read write"
}
```

## Proof Key for Code Exchange (PKCE)

### PKCE Methods

1. **S256 (Recommended):**
   - Generate a random `code_verifier`
   - Create `code_challenge` by SHA-256 hashing the verifier
   - Base64URL encode the hash

2. **Plain Method:**
   - `code_challenge` is the same as `code_verifier`
   - Less secure, use only when S256 is not possible

## Security Considerations

1. **Always use HTTPS** for all communication
2. **Validate `redirect_uri`** against registered client URIs
3. **Short-lived authorization codes** (typically 10 minutes)
4. **Single-use authorization codes**
5. **Validate PKCE code challenge and verifier**
6. **Use `state` parameter for CSRF protection**

## Client Registration Requirements

To use the Authorization Code grant, a client must:
- Be registered with the authorization server
- Have a valid `redirect_uri`
- Support PKCE
- Be capable of securely storing client credentials

## Sample Client Implementation

### Cross-Language PKCE Implementation Examples

Proof Key for Code Exchange (PKCE) can be implemented across multiple languages. Here are examples in Python, Node.js, and Go:

### Python Example with PKCE

```python
import base64
import hashlib
import secrets
import requests

def generate_code_verifier():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')

def generate_code_challenge(code_verifier):
    code_challenge = hashlib.sha256(code_verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode('ascii')

# Generate PKCE parameters
code_verifier = generate_code_verifier()
code_challenge = generate_code_challenge(code_verifier)

# Authorization request parameters
auth_params = {
    'response_type': 'code',
    'client_id': 'your_client_id',
    'redirect_uri': 'https://your-app.com/callback',
    'state': 'random_state_value',
    'code_challenge': code_challenge,
    'code_challenge_method': 'S256',
    'scope': 'read write'
}

# Token exchange
def exchange_code_for_token(authorization_code):
    token_params = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': 'https://your-app.com/callback',
        'client_id': 'your_client_id',
        'code_verifier': code_verifier
    }
    
    response = requests.post('https://dew-auth-server.com/oauth2/token', data=token_params)
    return response.json()
```

### Node.js Example with PKCE

```javascript
const crypto = require('crypto');
const axios = require('axios');

class PKCEClient {
  // Generate code verifier
  static generateCodeVerifier() {
    return crypto.randomBytes(32)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  // Generate code challenge
  static generateCodeChallenge(codeVerifier) {
    return crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  // Authorization request
  static async initiateAuthorizationRequest() {
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = this.generateCodeChallenge(codeVerifier);

    const authParams = {
      response_type: 'code',
      client_id: 'your_client_id',
      redirect_uri: 'https://your-app.com/callback',
      state: crypto.randomBytes(16).toString('hex'),
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      scope: 'read write'
    };

    // Redirect user to authorization server
    const authorizationUrl = `https://dew-auth-server.com/oauth2/authorize?${new URLSearchParams(authParams)}`;
    
    return { 
      authorizationUrl, 
      codeVerifier 
    };
  }

  // Token exchange
  static async exchangeCodeForToken(authorizationCode, codeVerifier) {
    try {
      const response = await axios.post('https://dew-auth-server.com/oauth2/token', 
        new URLSearchParams({
          grant_type: 'authorization_code',
          code: authorizationCode,
          redirect_uri: 'https://your-app.com/callback',
          client_id: 'your_client_id',
          code_verifier: codeVerifier
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      return response.data;
    } catch (error) {
      console.error('Token exchange failed:', error.response?.data || error.message);
      throw error;
    }
  }
}

// Usage example
async function authenticateUser() {
  try {
    // Step 1: Initiate Authorization
    const { authorizationUrl, codeVerifier } = PKCEClient.initiateAuthorizationRequest();
    
    // Redirect user to authorizationUrl
    // After user authorizes, receive authorization code via callback

    // Step 2: Exchange Code for Token
    const authorizationCode = '...'; // Received from callback
    const tokenResponse = await PKCEClient.exchangeCodeForToken(authorizationCode, codeVerifier);
    
    console.log('Access Token:', tokenResponse.access_token);
  } catch (error) {
    console.error('Authentication failed:', error);
  }
}
```

### Go Example with PKCE

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
)

type PKCEClient struct {
	ClientID     string
	RedirectURI string
}

// Generate cryptographically secure code verifier
func generateCodeVerifier() (string, error) {
	// Generate 32 random bytes
	verifier := make([]byte, 32)
	_, err := rand.Read(verifier)
	if err != nil {
		return "", err
	}

	// Base64URL encode without padding
	return base64.RawURLEncoding.EncodeToString(verifier), nil
}

// Generate code challenge using SHA-256
func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// Build authorization URL
func (c *PKCEClient) BuildAuthorizationURL() (string, string, error) {
	// Generate PKCE parameters
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return "", "", err
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Prepare authorization parameters
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURI},
		"state":                 {generateState()},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"read write"},
	}

	authorizationURL := fmt.Sprintf(
		"https://dew-auth-server.com/oauth2/authorize?%s", 
		params.Encode(),
	)

	return authorizationURL, codeVerifier, nil
}

// Exchange authorization code for tokens
func (c *PKCEClient) ExchangeCodeForToken(
	authorizationCode string, 
	codeVerifier string,
) (*TokenResponse, error) {
	// Prepare token exchange parameters
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorizationCode},
		"redirect_uri":  {c.RedirectURI},
		"client_id":     {c.ClientID},
		"code_verifier": {codeVerifier},
	}

	// Make HTTP POST request to token endpoint
	resp, err := http.PostForm(
		"https://dew-auth-server.com/oauth2/token", 
		params,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse token response
	var tokenResp TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// Generate random state for CSRF protection
func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Token response structure
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// Example usage
func main() {
	client := &PKCEClient{
		ClientID:     "your_client_id",
		RedirectURI: "https://your-app.com/callback",
	}

	// Step 1: Generate Authorization URL
	authURL, codeVerifier, err := client.BuildAuthorizationURL()
	if err != nil {
		fmt.Println("Error generating authorization URL:", err)
		return
	}

	fmt.Println("Visit this URL to authorize:", authURL)

	// Step 2: After user authorization, exchange code for tokens
	authorizationCode := "..." // Received from callback
	tokenResponse, err := client.ExchangeCodeForToken(authorizationCode, codeVerifier)
	if err != nil {
		fmt.Println("Token exchange failed:", err)
		return
	}

	fmt.Printf("Access Token: %s\n", tokenResponse.AccessToken)
}
```

### Implementation Notes

Each example demonstrates:
- Generating a secure code verifier
- Creating a code challenge
- Building an authorization URL
- Exchanging an authorization code for tokens
- Basic error handling

**Key Similarities Across Languages:**
- PKCE code verifier generation
- SHA-256 code challenge creation
- Base64URL encoding
- Handling authorization and token exchange requests

**Recommended Adaptations:**
- Use language-specific secure random generation
- Implement proper error handling
- Add logging and monitoring
- Securely store tokens
- Handle token refresh

## Troubleshooting

Common issues and their resolutions:

- **Invalid Authorization Code**: 
  - Ensure the code is not reused
  - Check that the code is within its expiration window
  - Verify the code was generated for the specific client

- **PKCE Validation Failure**:
  - Double-check code challenge generation method
  - Confirm `code_verifier` matches the original `code_challenge`
  - Ensure correct Base64URL encoding

- **Redirect URI Mismatch**:
  - Verify the redirect URI exactly matches the one registered for the client
  - Check for trailing slashes or protocol differences

- **Scope Issues**:
  - Confirm requested scopes are permitted for the client
  - Verify scope formatting (space-separated)

- **Client Authentication Problems**:
  - Ensure client secret is correct
  - Verify client is allowed to use the Authorization Code grant type

## Error Handling

Potential error responses during the flow:

```json
{
  "error": "invalid_request",
  "error_description": "Detailed error message"
}
```

Common error types:
- `invalid_request`: Malformed request
- `unauthorized_client`: Client not authorized for this grant type
- `access_denied`: User denied the authorization request
- `unsupported_response_type`: Invalid response type
- `invalid_scope`: Requested scope is invalid
- `server_error`: Internal server problem

## Related Documentation

- [OAuth 2.0 Specification (RFC 6749)](https://tools.ietf.org/html/rfc6749)
- [Proof Key for Code Exchange (PKCE) RFC 7636](https://tools.ietf.org/html/rfc7636)
- [Bearer Token Usage (RFC 6750)](https://tools.ietf.org/html/rfc6750)

## Support and Community

- Report issues on GitHub
- Contribute to the project
- Join the community discussion
- Check documentation for latest updates