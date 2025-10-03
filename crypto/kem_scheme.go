package crypto

import "encoding"

type KemPublicKey interface {
	encoding.BinaryMarshaler

	// Scheme returns the KemScheme this key is for
	Scheme() KemScheme
	// Equals checks if this key is equal to the passed one
	Equals(KemPublicKey) bool
}

type KemPrivateKey interface {
	encoding.BinaryMarshaler

	// Scheme returns the KemScheme this key is for
	Scheme() KemScheme
	// Equals checks if this key is equal to the passed one
	Equals(KemPrivateKey) bool
	// Public gets the KemPublicKey associated with this key
	Public() KemPublicKey
}

type KemScheme interface {
	// Name of the scheme
	Name() string

	// GenerateKeyPair generates a new key pair
	GenerateKeyPair() (KemPublicKey, KemPrivateKey, error)

	// Encapsulate a randomly generated secret returning this secret and the encapsulation using the KemPublicKey
	Encapsulate(key KemPublicKey) (ctxt, secret []byte, err error)

	// Decapsulate an encapsulation using the KemPrivateKey
	Decapsulate(key KemPrivateKey, ctxt []byte) ([]byte, error)

	// UnmarshalBinaryPrivateKey gets a KemPrivateKey given its binary representation
	UnmarshalBinaryPrivateKey([]byte) (KemPrivateKey, error)

	// UnmarshalBinaryPublicKey gets a KemPublicKey given its binary representation
	UnmarshalBinaryPublicKey([]byte) (KemPublicKey, error)

	// CiphertextSize is the length of the encapsulated data
	CiphertextSize() int

	// SharedKeySize is the length of the secret
	SharedKeySize() int

	// PrivateKeySize is the length of a marshaled KemPrivateKey
	PrivateKeySize() int

	// PublicKeySize is the length of a marshaled KemPublicKey
	PublicKeySize() int
}
