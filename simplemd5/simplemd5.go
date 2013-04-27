/*
This package uses the simplepass package namespace. Either use it in the place
of github.com/bmatsuo/go-simplepass or don't import its namespace. The latter
is preferable for portability.

	import (
		"github.com/bmatsuo/go-simplepass"
		_ "github.com/bmatsuo/go-simplepass/simplemd5"
	)

	func main() {
		fmt.Println(simplepass.JustHashString("md5", "dsupreme", "IDENTIFY"))
	}

*/
package simplepass

import (
	. "github.com/bmatsuo/go-simplepass"

	"crypto/md5"
)

var MD5 = Register("md5", NewSimpleFactory(md5.New))
