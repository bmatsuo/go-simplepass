package simplepass

import (
	. "github.com/bmatsuo/go-simplepass"

	"crypto/md5"
)

var MD5 = Register("md5", NewSimpleFactory(md5.New))
