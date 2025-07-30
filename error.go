package ezip

import "errors"

var (
	ErrInvalidPassword   = errors.New("invalid password")
	ErrInvalidAESKeySize = errors.New("invalid AES key size")
)
