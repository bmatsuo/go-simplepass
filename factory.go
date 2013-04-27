package simplepass

import (
	"fmt"
	"hash"
)

type Factory struct {
	ctor func() Interface
}

func (f *Factory) Hash(pass, salt []byte) ([]byte, error) {
	if f.ctor != nil {
		return f.ctor().Hash(pass, salt)
	}
	return nil, fmt.Errorf("no constructor")
}

func NewSimpleFactory(fn func() hash.Hash) *Factory {
	return &Factory{func() Interface {
		return Simple(fn())
	}}
}

func Simple(h hash.Hash) Interface {
	return Func(func(pass, salt []byte) ([]byte, error) {
		if h == nil {
			return nil, fmt.Errorf("no hash")
		}
		h.Reset()
		if _, err := h.Write(pass); err != nil {
			return nil, fmt.Errorf("hashing error")
		}
		if _, err := h.Write(salt); err != nil {
			return nil, fmt.Errorf("hashing error")
		}
		return h.Sum(nil), nil
	})
}
