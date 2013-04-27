// Copyright 2013, Bryan Matsuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Simplepass provides a common interface for computing secure password hashes.
Projects importing simplepass typically need only be aware of functions with
the form

	[Just](Salt|Hash|Check)[String]

The Salt functions generate salt with a specified amount of entropy. The Hash
functions compute hash values. The Check functions validate passwords against
hashed values. String functions deal with base64 urlencoded strings instead of
byte slices. Just functions disregard error messages returned by their
non-prefixed counterparts.
*/
package simplepass

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Used by the String family of functions. Defaults to base64.URLEncoding
var DefaultEncoding Encoding

// Readable string encoding for binary data
type Encoding interface {
	EncodeToString([]byte) string
	DecodeString(string) ([]byte, error)
}

// Validate a password against a precomputed hash.
func Check(name string, hash, pass, salt []byte) (bool, error) {
	p, err := Hash(name, pass, salt)
	if err != nil {
		return false, err
	}
	if len(p) != len(hash) {
		return false, nil
	}
	for i, c := range hash {
		if c != p[i] {
			return false, nil
		}
	}
	return true, nil
}

// Compute the hashed value of pass combined with salt
func Hash(name string, pass, salt []byte) ([]byte, error) {
	if h, ok := simplepass[name]; ok {
		return h.Hash(pass, salt)
	}
	return nil, fmt.Errorf("unkown hash: %q", name)
}

// Generate salt with a specified entropy.
func Salt(n int) ([]byte, error) {
	switch {
	case n == 0:
		n = 24
	case n < 16:
		return nil, fmt.Errorf("insufficient salt length: %d", n)
	}
	p := make([]byte, n)
	_, err := rand.Read(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// See Check(). The hash, and salt values must encoded by DefaultEncoding
func CheckString(name, hash, pass, salt string) (bool, error) {
	_hash, err := HashString(name, pass, salt)
	if err != nil {
		return false, err
	}
	return hash == _hash, nil
}

// See Hash(). The salt must be encoded by DefaultEncoding.
func HashString(name, pass, salt string) (string, error) {
	_salt, err := decodeString(salt)
	if err != nil {
		return "", fmt.Errorf("invalid salt: %v")
	}
	p, err := Hash(name, []byte(pass), _salt)
	return encodeToString(p), err
}

// See Salt(). Encodes salt with DefaultEncoding.
func SaltString(n int) (string, error) {
	p, err := Salt(n)
	return encodeToString(p), err
}

func encodeToString(p []byte) string {
	if DefaultEncoding == nil {
		return base64.URLEncoding.EncodeToString(p)
	}
	return DefaultEncoding.EncodeToString(p)
}

func decodeString(s string) ([]byte, error) {
	if DefaultEncoding == nil {
		return base64.URLEncoding.DecodeString(s)
	}
	return DefaultEncoding.DecodeString(s)
}
