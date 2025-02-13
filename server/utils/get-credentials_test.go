package utils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCredentialsFromBasicAuthHeader(t *testing.T) {
	type want struct {
		usr string // username
		pwd string // password
		err error
	}

	tests := []struct {
		name            string
		authHeaderValue string
		want
	}{
		{
			name:            "TestGetCredentialsFromBasicAuthHeader_EmptyHeader",
			authHeaderValue: "",
			want: want{
				usr: "",
				pwd: "",
				err: errors.New("authorization header is empty"),
			},
		},
		{
			name:            "TestGetCredentialsFromBasicAuthHeader_InvalidPrefix",
			authHeaderValue: "test ",
			want: want{
				usr: "",
				pwd: "",
				err: errors.New("authorization header does not start with 'Basic '"),
			},
		},
		{
			name:            "TestGetCredentialsFromBasicAuthHeader_InvalidCredentialsFormat",
			authHeaderValue: "Basic dGVzdDt0ZXN0", // "test;test"
			want: want{
				usr: "",
				pwd: "",
				err: errors.New("authorization header contains invalid credentials format"),
			},
		},
		{
			name:            "TestGetCredentialsFromBasicAuthHeader_EmptyUsername",
			authHeaderValue: "Basic OnRlc3Q=", // ":test"
			want: want{
				usr: "",
				pwd: "",
				err: errors.New("authorization header contains empty username or password"),
			},
		},
		{
			name:            "TestGetCredentialsFromBasicAuthHeader_EmptyPassword",
			authHeaderValue: "Basic dGVzdDo=", // "test:"
			want: want{
				usr: "",
				pwd: "",
				err: errors.New("authorization header contains empty username or password"),
			},
		},
		{
			name:            "TestGetCredentialsFromBasicAuthHeader_ValidCredentials",
			authHeaderValue: "Basic dGVzdDp0ZXN0", // "test:test"
			want: want{
				usr: "test",
				pwd: "test",
				err: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usr, pwd, err := GetCredentialsFromBasicAuthHeader(tt.authHeaderValue)
			assert.Equal(t, tt.want.usr, usr)
			assert.Equal(t, tt.want.pwd, pwd)
			assert.Equal(t, tt.want.err, err)
		})
	}
}
