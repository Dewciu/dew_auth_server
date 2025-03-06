# CORS Configuration for Dew Auth Server

## Overview

Cross-Origin Resource Sharing (CORS) is a mechanism that allows resources on a web page to be requested from a different domain than the one that served the page. This is particularly important for an OAuth server, as it often needs to be accessed from various client applications hosted on different domains.

The Dew Auth Server includes configurable CORS support that allows you to specify which origins can access your authorization endpoints.

## Configuration Options

CORS settings can be configured using environment variables:

| Environment Variable | Description | Default Value |
|---------------------|-------------|---------------|
| `CORS_ALLOW_ORIGINS` | Comma-separated list of allowed origins (e.g., `https://app1.example.com,https://app2.example.com`) | `*` (all origins) |
| `CORS_ALLOW_METHODS` | Comma-separated list of allowed HTTP methods | `GET,POST,PUT,PATCH,DELETE,OPTIONS` |
| `CORS_ALLOW_HEADERS` | Comma-separated list of allowed HTTP headers | `Origin,Content-Type,Accept,Authorization` |
| `CORS_EXPOSE_HEADERS` | Comma-separated list of headers exposed to the browser | `Content-Length,Content-Type` |
| `CORS_ALLOW_CREDENTIALS` | Whether to allow credentials (cookies, authorization headers) | `true` |
| `CORS_MAX_AGE` | How long (in seconds) browsers should cache preflight responses | `86400` (24 hours) |

## Example Configuration

Here's an example `.env` file configuration for a production environment:

```
# CORS Configuration
CORS_ALLOW_ORIGINS=https://example.com,https://admin.example.com
CORS_ALLOW_METHODS=GET,POST,OPTIONS
CORS_ALLOW_HEADERS=Origin,Content-Type,Accept,Authorization,X-Request-With
CORS_EXPOSE_HEADERS=Content-Length
CORS_ALLOW_CREDENTIALS=true
CORS_MAX_AGE=3600
```

## Security Considerations

### Restricting Origins

In production environments, it's recommended to explicitly list the allowed origins rather than using the wildcard `*`. This prevents unauthorized domains from making cross-origin requests to your server.

```
CORS_ALLOW_ORIGINS=https://app.example.com,https://admin.example.com
```

### Credentials and Wildcard Origins

When `CORS_ALLOW_CREDENTIALS` is set to `true`, browsers will not allow a wildcard `*` for the `Access-Control-Allow-Origin` header. If you need to support credentials, you must specify explicit origins.

### Minimal Exposure

Only expose headers that are necessary for your client applications to function correctly. Limiting exposed headers reduces the surface area for potential attacks.

## Testing CORS Configuration

You can test your CORS configuration using:

1. Browser developer tools (look for CORS errors in the Console)
2. A tool like cURL:

```bash
# Preflight request
curl -X OPTIONS https://dew-auth-server.com/oauth2/token \
  -H "Origin: https://example.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization,Content-Type" \
  -v
```