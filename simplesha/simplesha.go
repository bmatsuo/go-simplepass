/*
This package uses the simplepass package namespace. Either use it in the place
of github.com/bmatsuo/go-simplepass or don't import its namespace. The latter
is preferable for portability.

	import (
		"github.com/bmatsuo/go-simplepass"
		_ "github.com/bmatsuo/go-simplepass/simplesha"
	)

	func main() {
		fmt.Println(simplepass.JustHashString("sha512", "dsupreme", "IDENTIFY"))
		fmt.Println(simplepass.JustHashString("sha256", "dsupreme", "IDENTIFY"))
		fmt.Println(simplepass.JustHashString("sha1", "dsupreme", "IDENTIFY"))
	}

*/
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
