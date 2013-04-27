package simplepass

import (
	"bytes"
	"fmt"
	"hash"
	"testing"
)

type TestHash struct {
	buf *bytes.Buffer
	err error
}

func NewTestHash(err error) hash.Hash {
	return &TestHash{new(bytes.Buffer), err}
}

func (h *TestHash) Reset() {
	h.buf = new(bytes.Buffer)
}

func (h *TestHash) Write(p []byte) (int, error) {
	if h.err != nil {
		return 0, h.err
	}
	return h.buf.Write(p)

}

func (h *TestHash) Sum(p []byte) []byte {
	return append(p, h.buf.Bytes()...)
}

func (h *TestHash) Size() int {
	return 0
}

func (h *TestHash) BlockSize() int {
	return 0
}

func TestTestHash(t *testing.T) { // meta
	// a nil error causes successful writes
	h := NewTestHash(nil)
	switch n, err := h.Write([]byte("abc")); {
	case err != nil:
		t.Errorf("TestHash.Write retuned an error; %v", err)
	case n != 3:
		t.Errorf("TestHash.Write did not write all the bytes; %v", n)
	}

	// a non-nil error causes writes to return errors
	h = NewTestHash(fmt.Errorf("now it's broken"))
	if _, err := h.Write([]byte("def")); err == nil {
		t.Errorf("TestHash.Write returned success; %v", err)
	}
	if _, err := h.Write([]byte("def")); err == nil {
		t.Errorf("TestHash.Write returned success; %v", err)
	}

	// the sum is not empty when writes are successful
	h = NewTestHash(nil)
	h.Write([]byte("ghi"))
	switch p := h.Sum(nil); {
	case p == nil:
		t.Errorf("nil sum")
	case len(p) == 0:
		t.Errorf("empty sum")
	}
}

func NewTestSimple(err error) Interface {
	return Simple(NewTestHash(err))
}

func TestSimple(t *testing.T) {
	// successful writes to the hash.Hash given successful computing of the hash
	s := NewTestSimple(nil)
	if _, err := s.Hash([]byte("abc"), []byte("def")); err != nil {
		t.Errorf("Simple returned an error: %v", err)
	}

	// errors writing ot the hash.Hash are errors computing the hash
	s = NewTestSimple(fmt.Errorf("boo"))
	if _, err := s.Hash([]byte("abc"), []byte("def")); err == nil {
		t.Errorf("Simple returned success")
	}
}

func NewTestSimpleFactory(err error) *Factory {
	return NewSimpleFactory(func() hash.Hash {
		return NewTestHash(err)
	})
}

func TestSimpleFactory(t *testing.T) {
	// successful writes to the hash.Hash given successful computing of the hash
	f := NewTestSimpleFactory(nil)
	if _, err := f.Hash([]byte("abc"), []byte("def")); err != nil {
		t.Errorf("SimpleFactory returned error: %v", err)
	}

	// errors writing to the hash.Hash are errors computing the hash
	f = NewTestSimpleFactory(fmt.Errorf("die!"))
	if _, err := f.Hash([]byte("abc"), []byte("def")); err == nil {
		t.Errorf("SimpleFactory returned success on hash write error")
	}

	// the zero factory returns an error when hashing
	f = &Factory{}
	if _, err := f.Hash([]byte("abc"), []byte("def")); err == nil {
		t.Errorf("zero SimpleFactory returned success")
	}
}
