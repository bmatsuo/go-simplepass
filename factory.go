package simplepass

import (
	"fmt"
	"hash"
)

type Factory struct {
	New func() Interface
}

func (f *Factory) Hash(pass, salt []byte) ([]byte, error) {
	return f.New().Hash(pass, salt)
}

func NewSimpleFactory(fn func() hash.Hash) *Factory {
	return &Factory{func() Interface {
		return Simple(fn())
	}}
}

type Interface interface {
	Hash(pass, salt []byte) ([]byte, error)
}
type Func func(pass, salt []byte) ([]byte, error)

func (fn Func) Hash(pass, salt []byte) ([]byte, error) {
	return fn(pass, salt)
}

func Simple(h hash.Hash) Interface {
	return Func(func(pass, salt []byte) ([]byte, error) {
		h.Reset()
		if _, err := h.Write(pass); nil != err {
			return nil, fmt.Errorf("hashing error")
		}
		if _, err := h.Write(salt); nil != err {
			return nil, fmt.Errorf("hashing error")
		}
		return h.Sum(nil), nil
	})
}
