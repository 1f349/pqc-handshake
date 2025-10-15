// (C) 1f349 2025 - BSD-3-Clause License

package crypto

import (
	"errors"
	"github.com/cloudflare/circl/kem"
	"sync"
)

var ErrIncompatibleKey = errors.New("incompatible key")

var kemWrappedMap = make(map[kem.Scheme]*KemWrapper)
var slockKemWrappedMap = &sync.RWMutex{}

func getKemWrapper(scheme kem.Scheme) *KemWrapper {
	slockKemWrappedMap.RLock()
	defer slockKemWrappedMap.RUnlock()
	kemWrapped, ok := kemWrappedMap[scheme]
	if !ok {
		return nil
	}
	return kemWrapped
}

func addKemWrapper(scheme kem.Scheme) *KemWrapper {
	slockKemWrappedMap.Lock()
	defer slockKemWrappedMap.Unlock()
	if _, ok := kemWrappedMap[scheme]; !ok {
		kemWrappedMap[scheme] = &KemWrapper{scheme}
	}
	return kemWrappedMap[scheme]
}

// WrapKem a kem.Scheme
func WrapKem(scheme kem.Scheme) *KemWrapper {
	w := getKemWrapper(scheme)
	if w == nil {
		return addKemWrapper(scheme)
	}
	return w
}

// KemWrapper wraps kem.Scheme from github.com/cloudflare/circl for KemScheme
type KemWrapper struct {
	wrapped kem.Scheme
}

func (k KemWrapper) Name() string {
	return k.wrapped.Name()
}

func (k KemWrapper) GenerateKeyPair() (KemPublicKey, KemPrivateKey, error) {
	p, q, err := k.wrapped.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return &KemPublicKeyWrapper{p}, &KemPrivateKeyWrapper{q}, nil
}

func (k KemWrapper) Encapsulate(key KemPublicKey) (ctxt, secret []byte, err error) {
	if wk, ok := key.(*KemPublicKeyWrapper); ok {
		return k.wrapped.Encapsulate(wk.PublicKey)
	}
	return nil, nil, ErrIncompatibleKey
}

func (k KemWrapper) Decapsulate(key KemPrivateKey, ctxt []byte) ([]byte, error) {
	if wk, ok := key.(*KemPrivateKeyWrapper); ok {
		return k.wrapped.Decapsulate(wk.PrivateKey, ctxt)
	}
	return nil, ErrIncompatibleKey
}

func (k KemWrapper) UnmarshalBinaryPrivateKey(bytes []byte) (KemPrivateKey, error) {
	wk, err := k.wrapped.UnmarshalBinaryPrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return &KemPrivateKeyWrapper{wk}, nil
}

func (k KemWrapper) UnmarshalBinaryPublicKey(bytes []byte) (KemPublicKey, error) {
	wk, err := k.wrapped.UnmarshalBinaryPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return &KemPublicKeyWrapper{wk}, nil
}

func (k KemWrapper) CiphertextSize() int {
	return k.wrapped.CiphertextSize()
}

func (k KemWrapper) SharedKeySize() int {
	return k.wrapped.SharedKeySize()
}

func (k KemWrapper) PrivateKeySize() int {
	return k.wrapped.PrivateKeySize()
}

func (k KemWrapper) PublicKeySize() int {
	return k.wrapped.PublicKeySize()
}

// KemPublicKeyWrapper wraps kem.PublicKey  for KemPublicKey
type KemPublicKeyWrapper struct {
	kem.PublicKey
}

func (k KemPublicKeyWrapper) Scheme() KemScheme {
	return getKemWrapper(k.PublicKey.Scheme())
}

func (k KemPublicKeyWrapper) Equals(key KemPublicKey) bool {
	if wk, ok := key.(*KemPublicKeyWrapper); ok {
		return k.PublicKey.Equal(wk.PublicKey)
	}
	if wk, ok := key.(KemPublicKeyWrapper); ok {
		return k.PublicKey.Equal(wk.PublicKey)
	}
	return false
}

// KemPrivateKeyWrapper wraps kem.PrivateKey for KemPrivateKey
type KemPrivateKeyWrapper struct {
	kem.PrivateKey
}

func (k KemPrivateKeyWrapper) Scheme() KemScheme {
	return getKemWrapper(k.PrivateKey.Scheme())
}

func (k KemPrivateKeyWrapper) Equals(key KemPrivateKey) bool {
	if wk, ok := key.(*KemPrivateKeyWrapper); ok {
		return k.PrivateKey.Equal(wk.PrivateKey)
	}
	if wk, ok := key.(KemPrivateKeyWrapper); ok {
		return k.PrivateKey.Equal(wk.PrivateKey)
	}
	return false
}

func (k KemPrivateKeyWrapper) Public() KemPublicKey {
	return &KemPublicKeyWrapper{k.PrivateKey.Public()}
}
