package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashAndVerifyPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		password         string
		expectedHashFunc func(string) bool
		matchCompare     string
		shouldMatch      bool
	}{
		{
			name:     "Simple Password",
			password: "password123",
			expectedHashFunc: func(hash string) bool {
				// Check that hash is not empty and not the same as original password
				return hash != "" && hash != "password123"
			},
			matchCompare: "password123",
			shouldMatch:  true,
		},
		{
			name:     "Complex Password",
			password: "P@$$w0rd!123",
			expectedHashFunc: func(hash string) bool {
				return hash != "" && hash != "P@$$w0rd!123"
			},
			matchCompare: "P@$$w0rd!123",
			shouldMatch:  true,
		},
		{
			name:     "Empty Password",
			password: "",
			expectedHashFunc: func(hash string) bool {
				return hash != ""
			},
			matchCompare: "",
			shouldMatch:  true,
		},
		{
			name:     "Unicode Password",
			password: "пароль123", // Russian for "password123"
			expectedHashFunc: func(hash string) bool {
				return hash != "" && hash != "пароль123"
			},
			matchCompare: "пароль123",
			shouldMatch:  true,
		},
		{
			name:     "Wrong Password",
			password: "correct_password",
			expectedHashFunc: func(hash string) bool {
				return hash != "" && hash != "wrong_password"
			},
			matchCompare: "wrong_password",
			shouldMatch:  false,
		},
		{
			name:     "Case Sensitive",
			password: "Password123",
			expectedHashFunc: func(hash string) bool {
				return hash != "" && hash != "password123"
			},
			matchCompare: "password123",
			shouldMatch:  false,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Test HashPassword
			hash, err := HashPassword(tt.password)
			assert.NoError(t, err)
			assert.True(t, tt.expectedHashFunc(hash))

			// Test VerifyPassword
			match := VerifyPassword(tt.matchCompare, hash)
			assert.Equal(t, tt.shouldMatch, match)
		})
	}
}
