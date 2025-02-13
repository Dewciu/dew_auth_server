package utils

import (
	"encoding/base64"
	"errors"
)

// GetCredentialsFromBasicAuthHeader extracts the username and password from the Authorization header
// in the format "Basic <base64-encoded-username:password>"
// and returns the username and password.
// If the header is not in the correct format, it returns an error.
// Input is the authHeaderValue string - the value of the Authorization header
func GetCredentialsFromBasicAuthHeader(authHeaderValue string) (usr string, pwd string, err error) {
	const prefix = "Basic "

	if authHeaderValue == "" {
		return "", "", errors.New("authorization header is empty")
	}

	// Prefix check
	if len(authHeaderValue) < len(prefix) || authHeaderValue[0:len(prefix)] != prefix {
		return "", "", errors.New("authorization header does not start with 'Basic '")
	}

	authHeaderValue = authHeaderValue[len(prefix):]
	decodedBytes, err := base64.StdEncoding.DecodeString(authHeaderValue)
	if err != nil {
		return "", "", err
	}
	credentials := string(decodedBytes)

	// Split the credentials into username and password
	colonIndex := func(creds string) int {
		for i, c := range creds {
			if c == ':' {
				return i
			}
		}

		return -1
	}

	cIdx := colonIndex(credentials)

	if cIdx == -1 {
		return "", "", errors.New("authorization header contains invalid credentials format")
	}

	usr = credentials[:cIdx]
	pwd = credentials[cIdx+1:]

	if usr == "" || pwd == "" {
		return "", "", errors.New("authorization header contains empty username or password")
	}

	return usr, pwd, nil
}
