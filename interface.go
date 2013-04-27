package simplepass

var simplepass = make(map[string]Interface, 0)

// Register an interface with a new name.
func Register(name string, hash Interface) Interface {
	simplepass[name] = hash
	return hash
}

// Implemented for various hashing algorithms in another
type Interface interface {
	Hash(pass, salt []byte) ([]byte, error)
}

// Implements Interface
type Func func(pass, salt []byte) ([]byte, error)

func (fn Func) Hash(pass, salt []byte) ([]byte, error) {
	return fn(pass, salt)
}
