package protocol

import "errors"

var (
	ErrInvalidMagic       = errors.New("invalid magic bytes")
	ErrInvalidPacketSize  = errors.New("invalid packet size")
	ErrUnsupportedVersion = errors.New("unsupported protocol version")
	ErrIncorrectType      = errors.New("incorrect packet type")
	ErrUnsupportedType    = errors.New("unsupported packet type")
	ErrAuthFailed         = errors.New("authentication failed")
	ErrInvalidSessionID   = errors.New("invalid session ID")
	ErrInvalidNonce       = errors.New("invalid nonce")
	ErrReusedNonce        = errors.New("reused nonce")

	// Hello packet errors
	ErrUnsupportedTransport = errors.New("unsupported transport type")
	ErrUnsupportedSecurity  = errors.New("unsupported security type")
	ErrUnsupportedDirection = errors.New("unsupported direction type")
	ErrInvalidFlags         = errors.New("invalid flags")
	ErrInvalidChunkSize     = errors.New("invalid chunk size")
	ErrInvalidWarmup        = errors.New("invalid warmup period")
	ErrInvalidDuration      = errors.New("invalid duration")
)
