package constants

type RequestError string

const (
	InvalidRequest RequestError = "invalid_request"
	ServerError    RequestError = "server_error"
)
