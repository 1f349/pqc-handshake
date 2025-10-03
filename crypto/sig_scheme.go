package crypto

import "encoding"

type SigPublicKey interface {
	encoding.BinaryMarshaler

	// Scheme returns the SigScheme this key is for
	Scheme() SigScheme
	// Equals checks if this key is equal to the passed one
	Equals(SigPublicKey) bool
}

type SigPrivateKey interface {
	encoding.BinaryMarshaler

	// Scheme returns the SigScheme this key is for
	Scheme() SigScheme
	// Equals checks if this key is equal to the passed one
	Equals(SigPrivateKey) bool
	// Public gets the SigPublicKey associated with this key
	Public() SigPublicKey
}

type SigScheme interface {
	// Name of the scheme
	Name() string

	// GenerateKey generates a new key pair
	GenerateKey() (SigPublicKey, SigPrivateKey, error)

	// UnmarshalBinaryPrivateKey gets a SigPrivateKey given its binary representation
	UnmarshalBinaryPrivateKey([]byte) (SigPrivateKey, error)

	// UnmarshalBinaryPublicKey gets a SigPublicKey given its binary representation
	UnmarshalBinaryPublicKey([]byte) (SigPublicKey, error)

	// Sign a message given the SigPrivateKey
	Sign(key SigPrivateKey, msg []byte) ([]byte, error)

	// Verify a message given the SigPublicKey
	Verify(key SigPublicKey, msg []byte, sig []byte) (bool, error)

	// PublicKeySize is the length of a marshaled SigPublicKey
	PublicKeySize() int

	// PrivateKeySize is the length of the marshaled SigPrivateKey
	PrivateKeySize() int

	// SignatureSize is the length of the signature
	SignatureSize() int
}
