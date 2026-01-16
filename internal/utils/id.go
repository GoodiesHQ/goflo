package utils

import (
	"crypto/rand"

	"github.com/oklog/ulid/v2"
)

var entropy = rand.Reader

func NewULID() (ulid.ULID, error) {
	id, err := ulid.New(ulid.Now(), entropy)
	if err != nil {
		return ulid.ULID{}, err
	}
	return id, nil
}

func NewNonce() ([16]byte, error) {
	var nonce [16]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return [16]byte{}, err
	}
	return nonce, nil
}
