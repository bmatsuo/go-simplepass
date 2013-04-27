// Copyright 2013, Bryan Matsuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Simplepass makes working with securely hashed passwords easier.

	package main

	import (
		"fmt"
		"github.com/bmatsuo/go-simplepass"
		_ "github.com/bmatsuo/go-simplepass/simplesha"
	)

	type password struct{ hashed, salt string }

	var users = make(map[string]password, 0)

	func register(email, pass string) {
		salt := simplepass.JustSaltString(24)
		hashed := simplepass.JustHashString("sha512", pass, salt)
		users[email] = password{hashed, salt}
	}

	func authenticate(email, pass string) bool {
		user, ok := users[email]
		return ok && simplepass.JustCheckString("sha512", user.hashed, pass, user.salt)
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
	}

Projects importing simplepass typically need only be aware of functions
with the form.

	[Just](Salt|Hash|Check)[String]

The Salt functions generate salt with a specified amount of entropy. The Hash
functions compute hashes values. The Check functions validate passwords against
hashes. String functions deal with base64 urlencoded strings instead of byte
slices. Just functions disregard error messages returned by their non-prefixed
counterparts.
*/
package simplepass

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func Hash(name string, pass, salt []byte) ([]byte, error) {
	h := simplepass[name]
	if h == nil {
		return nil, fmt.Errorf("unkown hash: %q", name)
	}
	return h.Hash(pass, salt)
}
func HashString(name, pass, salt string) (string, error) {
	p, err := Hash(name, []byte(pass), []byte(salt))
	return base64.URLEncoding.EncodeToString(p), err
}
func JustHash(name string, pass, salt []byte) []byte {
	h, _ := Hash(name, pass, salt)
	return h
}
func JustHashString(name string, pass, salt string) string {
	h, _ := HashString(name, pass, salt)
	return h
}

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
func CheckString(name, hash, pass, salt string) (bool, error) {
	_hash, err := HashString(name, pass, salt)
	if err != nil {
		return false, err
	}
	return hash == _hash, nil
}
func JustCheck(name string, hash, pass, salt []byte) bool {
	b, _ := Check(name, hash, pass, salt)
	return b
}
func JustCheckString(name, hash, pass, salt string) bool {
	b, _ := CheckString(name, hash, pass, salt)
	return b
}

func Salt(n int) ([]byte, error) {
	if n == 0 {
		n = 24
	}
	if n < 16 {
		return nil, fmt.Errorf("insufficient salt length: %d", n)
	}
	p := make([]byte, n)
	_, err := rand.Read(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}
func SaltString(n int) (string, error) {
	p, err := Salt(n)
	return base64.URLEncoding.EncodeToString(p), err
}
func JustSalt(n int) []byte {
	p, _ := Salt(n)
	return p
}
func JustSaltString(n int) string {
	return base64.URLEncoding.EncodeToString(JustSalt(n))
}
