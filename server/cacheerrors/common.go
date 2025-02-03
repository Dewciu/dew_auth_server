package cacheerrors

type MissingClientIDError struct{}

func (e *MissingClientIDError) Error() string {
	return "missing client ID: the client ID is required but was not provided"
}

type MissingScopesError struct{}

func (e *MissingScopesError) Error() string {
	return "missing scopes: the scopes are required but were not provided"
}
