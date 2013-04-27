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

// Default encoding used by the String family of functions.
var DefaultEncoding Encoding

type Encoding interface {
	EncodeToString([]byte) string
	DecodeString(string) ([]byte, error)
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
func Hash(name string, pass, salt []byte) ([]byte, error) {
	if h, ok := simplepass[name]; ok {
		return h.Hash(pass, salt)
	}
	return nil, fmt.Errorf("unkown hash: %q", name)
}
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

func CheckString(name, hash, pass, salt string) (bool, error) {
	_hash, err := HashString(name, pass, salt)
	if err != nil {
		return false, err
	}
	return hash == _hash, nil
}
func HashString(name, pass, salt string) (string, error) {
	_pass, err := decodeString(pass)
	if err != nil {
		return "", fmt.Errorf("invalid password: %v", err)
	}
	_salt, err := decodeString(salt)
	if err != nil {
		return "", fmt.Errorf("invalid salt: %v")
	}
	p, err := Hash(name, _pass, _salt)
	return encodeToString(p), err
}
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
