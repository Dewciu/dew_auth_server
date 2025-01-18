# OAuth 2.0 Authorization Server

Welcome to the **OAuth 2.0 Authorization Server**! This server implements the **Authorization Code flow with PKCE**, as well as **Token Revocation** and **Token Introspection** endpoints, in accordance with [RFC 6749 (OAuth 2.0)](https://datatracker.ietf.org/doc/html/rfc6749) and [RFC 7636 (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636). It also demonstrates the use of the **state parameter** for CSRF protection and returns JSON-formatted responses wherever applicable.

Below is a brief overview of each endpoint and how they can be used. If you’d like more detail, see the OpenAPI specification file or the summaries in each section.

---

## Table of Contents

1. [Overview](#overview)
2. [Authorization Endpoint (`GET /oauth2/authorize`)](#authorization-endpoint)
3. [Token Endpoint (`POST /oauth2/token`)](#token-endpoint)
4. [Token Revocation Endpoint (`POST /oauth2/revoke`)](#token-revocation-endpoint)
5. [Token Introspection Endpoint (`POST /oauth2/introspect`)](#token-introspection-endpoint)
6. [Security Schemes](#security-schemes)
   - [OAuth 2.0 Authorization Code with PKCE](#oauth-20-authorization-code-with-pkce)
   - [Basic Authentication](#basic-authentication)
7. [License](#license)

---

## Overview

- **Specification**: OpenAPI 3.0.3  
- **Title**: OAuth 2.0 Authorization Server  
- **Version**: 1.0.0  
- **Description**:  
  This specification outlines:
  - **Authorization Code flow with PKCE** (Proof Key for Code Exchange)
  - **Token Revocation** and **Token Introspection** endpoints
  - Use of `state` parameter for additional security (CSRF protection)
  - Examples of request parameters and responses (mostly in JSON)

- **Server URL**: `https://dew-auth-server.com`

The **Authorization Code flow with PKCE** enhances the traditional OAuth 2.0 Authorization Code grant flow by adding a layer of security, especially for mobile or public clients (where a client secret cannot be stored securely). PKCE ensures the authorization code exchange cannot be intercepted or tampered with by requiring a `code_challenge` (derived from a `code_verifier`) during authorization, which is then verified at the token exchange stage.

---

## Authorization Endpoint

```
GET /oauth2/authorize
```

### Purpose
- Obtain an authorization code from the resource owner (the user).
- In the **PKCE** scenario, you send a `code_challenge` (derived from a `code_verifier`) to bind the authorization request to the subsequent token exchange.

### Required Query Parameters
- **`response_type`**: Must be `code`.
- **`client_id`**: Unique identifier of the client (registered with the authorization server).
- **`redirect_uri`**: URI where the user will be redirected after authorization.
- **`scope`**: Space-separated list of scopes requested.
- **`code_challenge`**: PKCE code challenge (Base64URL-encoded SHA256 of the `code_verifier` or plain if `code_challenge_method=plain`).
- **`code_challenge_method`**: Typically `S256` or `plain`.

### Optional Query Parameter
- **`state`**: An opaque value for protecting the client against cross-site request forgery (CSRF). It will be included as a query parameter when redirecting back to the client.

### Possible Responses
- **`302`**: Redirect to the client’s `redirect_uri` with either:
  - `code=<authorization_code>` (if successful), and optionally `state=<state_value>` if provided in the request, **or**
  - `error=<error_code>` if there was an issue (e.g., user denied, invalid request).
- **`4XX`**: Error response if:
  - The request is invalid.
  - The `client_id` is unknown.
  - The user denies the request.

---

## Token Endpoint

```
POST /oauth2/token
```

**Content-Type**: `application/x-www-form-urlencoded`

### Purpose
- Exchange an **authorization code** for an **access token** (and optionally a **refresh token**).
- Refresh an existing access token using a **refresh token**.

### Required Parameters
- **`grant_type`**: Must be `authorization_code` or `refresh_token`.
- When `grant_type=authorization_code`:
  - **`code`**: The authorization code received from the Authorization Endpoint.
  - **`redirect_uri`**: Must match the redirect URI used in the authorization request.
  - **`client_id`**: The public client ID (if applicable).
  - **`client_secret`**: Client secret for confidential clients (optional for public clients).
  - **`code_verifier`**: The original random string used to generate the `code_challenge` (for PKCE).
- When `grant_type=refresh_token`:
  - **`refresh_token`**: A valid refresh token.
  - **`client_id`** or **`client_secret`** may be required for client authentication depending on the server’s policy.

### Possible Responses
- **`200`**: Returns a JSON object containing:
  - **`access_token`**: The newly issued access token.
  - **`token_type`**: Typically `Bearer`.
  - **`expires_in`**: The lifetime of the access token in seconds.
  - **`refresh_token`**: A token to get new access tokens without requiring user interaction.
  - **`scope`**: The authorized scopes.
- **`4XX`**:
  - Returns an error object with:
    - **`error`**: The error code (e.g., `invalid_request`, `invalid_grant`).
    - **`error_description`**: A human-readable description of the error.

---

## Token Revocation Endpoint

```
POST /oauth2/revoke
```

**Content-Type**: `application/x-www-form-urlencoded`

### Purpose
- Notify the authorization server that a previously obtained token (access or refresh) is no longer needed, causing the server to invalidate it.

### Required Parameters
- **`token`**: The token to be revoked.
- **`token_type_hint`** (optional): A hint about the type of the token (e.g., `access_token` or `refresh_token`).
- **`client_id`**: Client identifier (for public clients).
- **`client_secret`**: Client secret (for confidential clients).

### Possible Responses
- **`200`**: The token has been revoked (or was already invalid). Often responds with an empty body or a simple JSON status.
- **`4XX`**: Indicates an invalid request or unauthorized client credentials.

---

## Token Introspection Endpoint

```
POST /oauth2/introspect
```

**Content-Type**: `application/x-www-form-urlencoded`

### Purpose
- Allows resource servers (or authorized clients) to query the authorization server about the **active state** of an OAuth 2.0 token and retrieve additional metadata about it.

### Required Parameters
- **`token`**: The token to introspect.
- **`token_type_hint`** (optional): A hint about the type of the token.
- **`client_id`**: Client ID (if required for authentication).
- **`client_secret`**: Client secret (if required).

### Possible Responses
- **`200`**: Returns a JSON object describing token state and metadata:
  - **`active`** (boolean): Whether the token is active.
  - **`scope`**, **`client_id`**, **`username`**, **`token_type`**, **`exp`**, **`iat`**, **`nbf`**, **`sub`**, **`aud`**, **`iss`**, etc.
- **`4XX`**: Indicates an invalid token, missing/invalid credentials, or other request errors.

---

## Security Schemes

### OAuth 2.0 Authorization Code with PKCE

Declared in the `components.securitySchemes` section as `OAuth2AuthorizationCode`, this scheme:

- Uses the `authorizationCode` flow.
- `authorizationUrl`: `https://your-auth-server.com/oauth2/authorize`
- `tokenUrl`: `https://your-auth-server.com/oauth2/token`
- Scopes:
  - **read**: Read access
  - **write**: Write access

PKCE (Proof Key for Code Exchange) is strongly recommended for public clients or native apps to mitigate the risk of authorization code interception.

### Basic Authentication

Declared in `components.securitySchemes` as `BasicAuth`. Typically used by **confidential** clients to authenticate with the token, revocation, and introspection endpoints:

- Uses HTTP Basic Authentication.
- Pass `client_id` and `client_secret` in the `Authorization` header, base64-encoded.

---

## License

This project follows OAuth 2.0 specifications. Please ensure compliance with local data protection and privacy regulations (e.g., GDPR, CCPA) when handling user information.

For any questions or issues related to the OAuth 2.0 Authorization Server or this specification, please open an issue or contact the maintainers.

**Thank you for using the OAuth 2.0 Authorization Server!** If you have any suggestions or feedback, feel free to contribute or reach out.  