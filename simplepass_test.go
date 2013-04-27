package simplepass

import (
	"fmt"
	"testing"
)

var TestI Interface = Register("test", NewTestSimpleFactory(nil))
var TestErrI Interface = Register("testerr", NewTestSimpleFactory(fmt.Errorf("testerr")))

func TestSalt(t *testing.T) {
	// zero len defaults to something reasonable
	switch salt, err := Salt(0); {
	case err != nil:
		t.Errorf("unexpected error: %v", err)
	case len(salt) < 16:
		t.Errorf("short salt: %v", len(salt))
	}
	// insecure salts are errors
	if salt, err := Salt(5); err == nil {
		t.Errorf("unexpected success: %x", salt)
	}
	// default string does not have trailing padding
	switch salt, err := SaltString(0); {
	case err != nil:
		t.Errorf("unexpected error: #v", err)
	case len(salt) < 16: // FIXME
		t.Errorf("short salt: %v", len(salt))
	case salt[len(salt)-1] == '=':
		t.Errorf("trailing padding: %v", salt)
	}
}
func TestHash(t *testing.T) {
	if hashed, err := Hash("testerr", []byte("abc"), []byte("def")); err == nil {
		t.Errorf("unexpected success: %x", hashed)
	}
	switch hashed, err := Hash("test", []byte("abc"), []byte("def")); {
	case err != nil:
		t.Errorf("unexpected error: %v", err)
	case len(hashed) == 0:
		t.Errorf("empty hashed value")
	}
}
func TestCheck(t *testing.T) {
	// successful check
	switch ok, err := Check("test", []byte("abcdef"), []byte("abc"), []byte("def")); {
	case err != nil:
		t.Errorf("unexpected error: %v", err)
	case !ok:
		t.Errorf("unexpected failure: %x", JustHash("test", []byte("abc"), []byte("def")))
	}
	// failed check
	switch ok, err := Check("test", []byte("ah hah!"), []byte("abc"), []byte("def")); {
	case err != nil:
		t.Errorf("unexpected error: %v", err)
	case ok:
		t.Errorf("unexpected success: %x", JustHash("test", []byte("abc"), []byte("def")))
	}
	// hash.Hash failure implies Check failure
	switch ok, err := Check("testerr", []byte("abcdef"), []byte("abc"), []byte("def")); {
	case err == nil:
		t.Errorf("unexpected error: %v", err)
	case ok:
		t.Errorf("unexpected success")
	}
}
