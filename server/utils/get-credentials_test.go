package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCredentialsFromBasicAuthHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		authHeader     string
		expectedUser   string
		expectedPass   string
		expectError    bool
		expectedErrMsg string
	}{
		{
			name:           "Valid Authorization Header",
			authHeader:     "Basic dXNlcm5hbWU6cGFzc3dvcmQ=", // "username:password" in base64
			expectedUser:   "username",
			expectedPass:   "password",
			expectError:    false,
			expectedErrMsg: "",
		},
		{
			name:           "Empty Authorization Header",
			authHeader:     "",
			expectedUser:   "",
			expectedPass:   "",
			expectError:    true,
			expectedErrMsg: "authorization header is empty",
		},
		{
			name:           "Invalid Prefix",
			authHeader:     "Bearer dXNlcm5hbWU6cGFzc3dvcmQ=",
			expectedUser:   "",
			expectedPass:   "",
			expectError:    true,
			expectedErrMsg: "authorization header does not start with 'Basic '",
		},
		{
			name:           "Invalid Base64",
			authHeader:     "Basic invalid-base64!@#$",
			expectedUser:   "",
			expectedPass:   "",
			expectError:    true,
			expectedErrMsg: "illegal base64 data",
		},
		{
			name:           "No Colon Separator",
			authHeader:     "Basic dXNlcm5hbWVwYXNzd29yZA==", // "usernamepassword" in base64
			expectedUser:   "",
			expectedPass:   "",
			expectError:    true,
			expectedErrMsg: "authorization header contains invalid credentials format",
		},
		{
			name:           "Empty Username",
			authHeader:     "Basic OnBhc3N3b3Jk", // ":password" in base64
			expectedUser:   "",
			expectedPass:   "",
			expectError:    true,
			expectedErrMsg: "authorization header contains empty username or password",
		},
		{
			name:           "Empty Password",
			authHeader:     "Basic dXNlcm5hbWU6", // "username:" in base64
			expectedUser:   "",
			expectedPass:   "",
			expectError:    true,
			expectedErrMsg: "authorization header contains empty username or password",
		},
		{
			name:           "Special Characters In Credentials",
			authHeader:     "Basic dXNlckAjJCU6cGFzc0AjJCU=", // "user@#$%:pass@#$%" in base64
			expectedUser:   "user@#$%",
			expectedPass:   "pass@#$%",
			expectError:    false,
			expectedErrMsg: "",
		},
		{
			name:           "Unicode Characters In Credentials",
			authHeader:     "Basic dXNlcsOhw6jDrzpwYXNzw6HDqMOv", // "useráèï:passáèï" in base64
			expectedUser:   "useráèï",
			expectedPass:   "passáèï",
			expectError:    false,
			expectedErrMsg: "",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user, pass, err := GetCredentialsFromBasicAuthHeader(tt.authHeader)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
				assert.Empty(t, user)
				assert.Empty(t, pass)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUser, user)
				assert.Equal(t, tt.expectedPass, pass)
			}
		})
	}
}
