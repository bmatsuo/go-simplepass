package simplepass

import "encoding/base64"

func JustCheck(name string, hash, pass, salt []byte) bool {
	b, _ := Check(name, hash, pass, salt)
	return b
}
func JustHash(name string, pass, salt []byte) []byte {
	h, _ := Hash(name, pass, salt)
	return h
}
func JustSalt(n int) []byte {
	p, _ := Salt(n)
	return p
}

func JustCheckString(name, hash, pass, salt string) bool {
	b, _ := CheckString(name, hash, pass, salt)
	return b
}
func JustHashString(name string, pass, salt string) string {
	h, _ := HashString(name, pass, salt)
	return h
}
func JustSaltString(n int) string {
	return base64.URLEncoding.EncodeToString(JustSalt(n))
}
