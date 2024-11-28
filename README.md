# **Dew OAuth 2.0 Server Documentation**

This documentation describes the OAuth 2.0 server implementation with support for **PKCE** and **opaque tokens**. The OAuth server manages user authentication, token issuance, introspection, and token revocation.

---

## **Endpoints**

### **1. Authorization Endpoint**

**URL**: `/authorize`  
**Method**: `GET`

#### **Description**
Initiates the authorization flow with PKCE. Returns an authorization code upon successful user authentication.

#### **Parameters**
| Name                   | Type   | Required | Description                                                                   |
|------------------------|--------|----------|-------------------------------------------------------------------------------|
| `response_type`        | String | Yes      | Must be `code`.                                                               |
| `client_id`            | String | Yes      | Client identifier.                                                            |
| `redirect_uri`         | String | Yes      | Registered callback URL for redirection.                                      |
| `scope`                | String | Yes      | Space-separated list of requested permissions.                                |
| `state`                | String | No       | Random string for CSRF protection.                                            |
| `code_challenge`       | String | Yes      | The PKCE code challenge (hashed code verifier).                               |
| `code_challenge_method`| String | Yes      | Must be `S256` for SHA-256 hashing.                                           |

#### **Response**

**Success**:
- **HTTP Status Code**: `302 Found` (Redirect to the `redirect_uri` with parameters)

Query Parameters in Redirect:
- `code`: Authorization code.
- `state`: Echoed back from the request (if provided).

**Error**:
- **HTTP Status Code**: `400 Bad Request`
- **Possible Reasons**:
  - Missing or invalid parameters (`client_id`, `redirect_uri`, `code_challenge`).
  - Invalid `response_type` (not `code`).
- **Error Response** (redirected with `error` and `error_description`):
  ```json
  {
    "error": "invalid_request",
    "error_description": "The client_id is invalid."
  }
  ```

---

### **2. Token Endpoint**

**URL**: `/token`  
**Method**: `POST`

#### **Description**
Exchanges an authorization code for an access token.

#### **Parameters**
| Name            | Type   | Required | Description                                                               |
|-----------------|--------|----------|---------------------------------------------------------------------------|
| `grant_type`    | String | Yes      | Must be `authorization_code`.                                             |
| `code`          | String | Yes      | The authorization code received from the `/authorize` endpoint.           |
| `redirect_uri`  | String | Yes      | Must match the `redirect_uri` used in the `/authorize` request.           |
| `client_id`     | String | Yes      | Client identifier.                                                        |
| `code_verifier` | String | Yes      | The original code verifier string for PKCE validation.                    |

#### **Response**

**Success**:
- **HTTP Status Code**: `200 OK`
- **Response Body**:
  ```json
  {
    "access_token": "opaque-access-token",
    "expires_in": 3600,
    "scope": "read write",
    "token_type": "Bearer"
  }
  ```

**Error**:
- **HTTP Status Code**: `400 Bad Request`
- **Possible Reasons**:
  - Invalid `grant_type` (not `authorization_code`).
  - Authorization code is expired, invalid, or already used.
  - PKCE validation failed.
- **Error Response**:
  ```json
  {
    "error": "invalid_grant",
    "error_description": "The authorization code is invalid or expired."
  }
  ```

---

### **3. Introspection Endpoint**

**URL**: `/introspect`  
**Method**: `POST`

#### **Description**
Validates an access token and retrieves associated metadata.

#### **Parameters**
| Name   | Type   | Required | Description                                       |
|--------|--------|----------|---------------------------------------------------|
| `token` | String | Yes      | The access token to validate.                    |

#### **Response**

**Success**:
- **HTTP Status Code**: `200 OK`
- **Response Body** (for a valid token):
  ```json
  {
    "active": true,
    "scope": "read write",
    "user_id": "123",
    "roles": ["admin", "editor"],
    "client_id": "client123",
    "exp": 1618321725
  }
  ```

**Error**:
- **HTTP Status Code**: `200 OK`
- **Response Body** (for an invalid token):
  ```json
  {
    "active": false
  }
  ```

---

### **4. Revoke Token Endpoint**

**URL**: `/revoke`  
**Method**: `POST`

#### **Description**
Allows clients to revoke access tokens, effectively rendering them invalid.

#### **Parameters**
| Name    | Type   | Required | Description                                      |
|---------|--------|----------|--------------------------------------------------|
| `token` | String | Yes      | The token to revoke.                             |

#### **Response**

**Success**:
- **HTTP Status Code**: `200 OK`
- **Response Body**:
  ```json
  {
    "message": "Token successfully revoked"
  }
  ```

**Error**:
- **HTTP Status Code**: `400 Bad Request`
- **Possible Reasons**:
  - Token is invalid or already revoked.
- **Error Response**:
  ```json
  {
    "error": "invalid_request",
    "error_description": "The token is invalid or already revoked."
  }
  ```