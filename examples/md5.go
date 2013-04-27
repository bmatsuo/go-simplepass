package main

import (
	"fmt"
	"github.com/bmatsuo/go-simplepass"
	_ "github.com/bmatsuo/go-simplepass/simplemd5"
)

type password struct{ hashed, salt string }

var users = make(map[string]password, 0) // user datastore

func register(email, pass string) {
	salt := simplepass.JustSaltString(24)
	hashed := simplepass.JustHashString("md5", pass, salt)
	users[email] = password{hashed, salt} // stupid
}

func authenticate(email, pass string) bool {
	user, ok := users[email]
	return ok && simplepass.JustCheckString("md5", user.hashed, pass, user.salt)
}

func main() {
	register("bingo@bango.com", "password")
	register("boo@g-g-ghostmail.com", "ahh!")
	register("ya@zoo.com", "letmein")
	fmt.Println(authenticate("ya@zoo.com", "password"))
	fmt.Println(authenticate("ya@zoo.com", "god"))
	fmt.Println(authenticate("ya@zoo.com", "letmein"))
	fmt.Println(authenticate("bingo@bango.com", "brute force!@#$!@"))
	fmt.Println(authenticate("bingo@bango.com", "password"))

	salt := simplepass.JustSaltString(0)
	fmt.Println(simplepass.JustHashString("md5", "secrets", salt))
}
