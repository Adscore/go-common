package adscoreErrors

type VersionError struct {
	message string
}

func (e *VersionError) Error() string {
	return e.message
}

func NewVersionError(message string) *VersionError {
	return &VersionError{message: message}
}

type ParseError struct {
	message string
}

func (e *ParseError) Error() string {
	return e.message
}

func NewParseError(message string) *ParseError {
	return &ParseError{message: message}
}

type VerifyError struct {
	message string
}

func (e *VerifyError) Error() string {
	return e.message
}

func NewVerifyError(message string) *VerifyError {
	return &VerifyError{message: message}
}
