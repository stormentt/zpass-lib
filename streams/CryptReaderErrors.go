package streams

type UncheckedError struct {
}

type InvalidStreamError struct {
}

type StreamIncompleteError struct {
}

func (e *UncheckedError) Error() string {
	return "CryptReader was not checked before reading"
}

func (e *InvalidStreamError) Error() string {
	return "Attempted to read from a stream that failed HMAC checking"
}

func (e *StreamIncompleteError) Error() string {
	return "Attempted to read from a stream that is too short"
}
