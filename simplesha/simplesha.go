package simplepass

import (
	. "github.com/bmatsuo/go-simplepass"

	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

var (
	SHA1   = Register("sha1", NewSimpleFactory(sha1.New))
	SHA512 = Register("sha512", NewSimpleFactory(sha512.New))
	SHA256 = Register("sha256", NewSimpleFactory(sha256.New))
)
